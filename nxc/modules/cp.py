"""Probe additional common HTTP/HTTPS ports on each target. Useful for
subnet sweeps where you want to find web services on non-standard ports
that nxc won't hit by default.
"""
import contextlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from nxc.helpers.misc import CATEGORY


# Common HTTP/HTTPS ports. Ordered by likelihood so the user sees hits
# sooner. De-duped as a list rather than a set so we preserve scan order
# (set ordering is insertion-ordered in CPython but we'd rather be explicit).
DEFAULT_PORTS = [
    80, 443, 8080, 8443, 8000, 8888, 8081, 8090, 8001, 8008,
    5000, 3000, 9000, 9090, 9091, 4000, 4040, 7000, 7001,
    9200, 5601, 9418,  # elasticsearch, kibana, git
]
SSL_PORTS = {443, 8443, 4443, 9443, 7443, 9200}


class NXCModule:
    """
    Probe common HTTP/HTTPS ports on each target and report a one-line
    summary per port that responds. Output:

        cp | 10.0.0.1:80    301  nginx/1.18  (Welcome)
        cp | 10.0.0.1:443   200  nginx/1.18  (App)         [SSL]
        cp | 10.0.0.1:8080  401  Apache-Coyote (Tomcat)

    Options:
        PORTS     Comma-separated list of ports to probe. Default: common HTTP/HTTPS ports.
        TIMEOUT   Per-port timeout in seconds. Default: 3
        OPEN_ONLY Only print ports that returned a response. Default: true
        WORKERS   Concurrent port probes per host. Default: 10

    Module by @claude
    """

    name = "cp"
    description = "Compact common-ports scan: probe ~20 HTTP/HTTPS ports per host and summarize"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.ports = DEFAULT_PORTS
        self.timeout = 3
        self.open_only = True
        self.workers = 10

    def options(self, context, module_options):
        """
        PORTS     Comma-separated list of ports. Default: common HTTP/HTTPS set
        TIMEOUT   Per-port timeout in seconds. Default: 3
        OPEN_ONLY Only print ports that responded. Default: true
        WORKERS   Concurrent port probes per host. Default: 10
        """
        raw = module_options.get("PORTS", "")
        if raw:
            try:
                self.ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
            except ValueError:
                context.log.fail(f"PORTS must be a comma-separated list of integers, got {raw!r}")
                self.ports = DEFAULT_PORTS
        self.timeout = int(module_options.get("TIMEOUT", 3))
        self.open_only = module_options.get("OPEN_ONLY", "true").lower() != "false"
        self.workers = max(1, int(module_options.get("WORKERS", 10)))

    def _probe_port(self, host, port, user_agent, verify):
        scheme = "https" if port in SSL_PORTS else "http"
        # IPv6 hosts come in raw — bracket them.
        host_part = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        port_part = "" if port == default_port else f":{port}"
        url = f"{scheme}://{host_part}{port_part}/"
        try:
            r = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=verify,
                stream=True,
                headers={"User-Agent": user_agent or "Mozilla/5.0 NetExec/HTTP"},
            )
            # Just read a small chunk so we can extract a server header — body
            # is discarded.
            body = b""
            with contextlib.suppress(Exception):
                for chunk in r.iter_content(chunk_size=4096):
                    if chunk:
                        body = chunk
                        break
            with contextlib.suppress(Exception):
                r.close()
            return port, r.status_code, r.headers.get("Server", "").strip(), body
        except requests.exceptions.SSLError:
            return port, None, "SSL-ERR", b""
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return port, None, None, b""
        except Exception as e:
            self.context.log.debug(f"cp probe error {url}: {e}")
            return port, None, None, b""

    def on_login(self, context, connection):
        self.context = context
        host = connection.host
        ua = getattr(connection.args, "user_agent", None)
        verify = not getattr(connection.args, "no_verify", False)

        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = [ex.submit(self._probe_port, host, p, ua, verify) for p in self.ports]
            for f in as_completed(futures):
                with contextlib.suppress(Exception):
                    results.append(f.result())

        results.sort(key=lambda x: x[0])
        open_count = 0
        for port, status, server, _ in results:
            if status is None:
                if not self.open_only:
                    context.log.display(f"{host}:{port:<5} (closed/no response)")
                continue
            open_count += 1
            scheme = "https" if port in SSL_PORTS else "http"
            ssl_tag = "  [SSL]" if scheme == "https" else ""
            server_str = server if server else "?"
            context.log.highlight(f"{host}:{port:<5} {status}  {server_str}{ssl_tag}")
        # Always emit a one-line summary so a silent module result on a
        # /24 doesn't look like a crash.
        context.log.display(f"{host}  {open_count}/{len(self.ports)} ports responded")
