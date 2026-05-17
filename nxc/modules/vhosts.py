"""Virtual-host enumeration. A single IP often serves many sites that only
respond when the right Host header is sent. This module:

  1. Captures a baseline response (with the host's IP as Host header).
  2. Pulls candidate hostnames from the cert's SANs (free, high-signal).
  3. Adds common subdomain prefixes against the target's apparent domain.
  4. Optionally reads a user wordlist via WORDLIST=<path>.
  5. For each candidate, sends GET / with Host: <candidate> and reports
     responses that diverge from the baseline.
"""
import contextlib
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from nxc.helpers.misc import CATEGORY


COMMON_PREFIXES = [
    "www", "mail", "smtp", "imap", "webmail", "vpn", "remote", "portal",
    "admin", "intranet", "extranet", "internal", "owa", "exchange", "autodiscover",
    "api", "api-v1", "api-v2", "dev", "test", "staging", "stage", "uat", "qa",
    "git", "gitlab", "gitea", "jenkins", "ci", "build", "deploy",
    "jira", "confluence", "wiki", "kibana", "grafana", "prometheus",
    "vcenter", "esxi", "vsphere",
    "blog", "shop", "store", "support", "help",
    "old", "backup", "secret", "hidden",
]


class NXCModule:
    """
    Probe for virtual hosts on the target IP by varying the Host header.

    Pulls candidate hostnames from the TLS cert's SANs (if HTTPS), the
    target FQDN (if you gave a hostname not an IP), a built-in list of
    common prefixes, and an optional user wordlist.

    Output:
        vhosts | 10.0.0.1:443  baseline: 200 size=4521 hash=ab12cd34
        vhosts | 10.0.0.1:443  [!] admin.example.com  200 size=12044 (title:Admin Console)
        vhosts | 10.0.0.1:443  [!] api.example.com    401 size=128

    Options:
        WORDLIST       Path to a newline-separated wordlist of hostnames or prefixes
        DOMAIN         Override the apparent domain (used with prefixes). Default: inferred from target
        TIMEOUT        Per-request timeout. Default: 4
        WORKERS        Concurrent probes. Default: 8
        MIN_DIFF_BYTES Smallest body-size delta to treat as a real vhost. Default: 64

    Module by @claude
    """

    name = "vhosts"
    description = "Probe virtual hosts via Host-header variation; pulls candidates from cert SANs + common prefixes"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.wordlist = None
        self.domain = None
        self.timeout = 4
        self.workers = 8
        self.min_diff = 64
        self._seen = set()
        self._lock = threading.Lock()

    def options(self, context, module_options):
        """
        WORDLIST       Path to a wordlist (one hostname/prefix per line)
        DOMAIN         Override the apparent domain
        TIMEOUT        Per-request timeout in seconds. Default: 4
        WORKERS        Concurrent probes. Default: 8
        MIN_DIFF_BYTES Min body-size delta to treat as a real vhost. Default: 64
        """
        self.wordlist = module_options.get("WORDLIST")
        self.domain = module_options.get("DOMAIN")
        self.timeout = int(module_options.get("TIMEOUT", 4))
        self.workers = max(1, int(module_options.get("WORKERS", 8)))
        self.min_diff = int(module_options.get("MIN_DIFF_BYTES", 64))

    def _cert_sans(self, host, port):
        """Best-effort SANs lookup. Returns (non_wildcards, wildcard_bases)
        where non_wildcards are hostnames to probe directly and wildcard_bases
        are domains (with the leading *. stripped) the caller should expand
        prefixes against.
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            self.context.log.debug("cryptography not installed; skipping SAN lookup")
            return [], []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der, default_backend())
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except Exception as e:
            self.context.log.debug(f"SAN lookup failed: {e}")
            return [], []

        plain = []
        wildcards = []
        for n in ext.value:
            v = str(n.value).strip().lower()
            if not v:
                continue
            if v.startswith("*."):
                wildcards.append(v[2:])
            else:
                plain.append(v)
        return plain, wildcards

    def _load_wordlist(self):
        if not self.wordlist:
            return []
        try:
            with open(self.wordlist, encoding="utf-8", errors="replace") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except OSError as e:
            self.context.log.fail(f"Cannot read wordlist {self.wordlist}: {e}")
            return []

    def _build_candidates(self, connection):
        cands = set()
        prefix_bases = set()
        host = connection.host

        # 1) Cert SANs (HTTPS only). Non-wildcards become direct candidates;
        # wildcards feed prefix_bases so we expand them.
        if getattr(connection, "is_ssl", False):
            plain, wildcards = self._cert_sans(host, connection.port)
            for san in plain:
                if san and san != host:
                    cands.add(san)
            for wc in wildcards:
                prefix_bases.add(wc)

        # 2) Hostname the user typed (if not an IP)
        hostname = getattr(connection, "hostname", None)
        if hostname and hostname != host:
            cands.add(hostname.lower())

        # 3) Inferred or user-supplied domain → prefix_bases
        if self.domain:
            prefix_bases.add(self.domain.lower())
        if hostname and "." in hostname and not hostname.replace(".", "").isdigit():
            prefix_bases.add(hostname.split(".", 1)[1].lower())

        for base in prefix_bases:
            for p in COMMON_PREFIXES:
                cands.add(f"{p}.{base}")

        # 4) User wordlist: entries with a dot are full hostnames, otherwise
        # treat as a prefix to combine with each prefix_base.
        for entry in self._load_wordlist():
            entry = entry.lower()
            if "." in entry:
                cands.add(entry)
            else:
                for base in prefix_bases:
                    cands.add(f"{entry}.{base}")

        return sorted(cands)

    def _probe(self, connection, host_header, baseline):
        try:
            r, body_bytes, body_text = connection.request_path(
                "/", headers={"Host": host_header}, timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"vhost probe error {host_header}: {e}")
            return

        status = r.status_code
        size = len(body_bytes)
        b_status, b_size = baseline
        # Diverges from baseline = real vhost. We treat a hit as either a
        # different status code OR a body size diff >= MIN_DIFF_BYTES.
        if status == b_status and abs(size - b_size) < self.min_diff:
            return
        # Dedup so cert SAN aliases like `www.x.com` and `x.com` that point at
        # the same vhost don't both show up.
        bucket = size // max(self.min_diff, 1)
        sig = (status, bucket)
        with self._lock:
            if sig in self._seen:
                return
            self._seen.add(sig)
        host_port = f"{connection.host}:{connection.port}"
        title = ""
        with contextlib.suppress(Exception):
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body_text, "html.parser")
            if soup.title and soup.title.string:
                title = f"  (title:{' '.join(soup.title.string.split())[:60]})"
        self.context.log.highlight(f"{host_port}  [!] {host_header}  {status} size={size}{title}")

    def _baseline(self, connection):
        """Capture the response for a deliberately-invalid Host header so we
        know what the default vhost looks like.
        """
        try:
            r, body_bytes, _ = connection.request_path(
                "/",
                headers={"Host": f"nxc-baseline-{connection.host}.invalid"},
                timeout=self.timeout,
            )
            return r.status_code, len(body_bytes)
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"vhost baseline error: {e}")
            return None

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session not initialized")
            return

        baseline = self._baseline(connection)
        if baseline is None:
            context.log.fail("Failed to capture vhost baseline; aborting")
            return
        host_port = f"{connection.host}:{connection.port}"
        context.log.display(f"{host_port}  baseline: HTTP {baseline[0]} size={baseline[1]}")

        candidates = self._build_candidates(connection)
        if not candidates:
            context.log.display(f"{host_port}  no candidates to probe (supply WORDLIST= or DOMAIN= for prefixes)")
            return

        context.log.display(f"{host_port}  probing {len(candidates)} candidates")
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = [ex.submit(self._probe, connection, c, baseline) for c in candidates]
            for f in as_completed(futures):
                with contextlib.suppress(Exception):
                    f.result()
