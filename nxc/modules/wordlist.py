"""Content discovery via wordlist. Probe each entry as a path, skip
catch-all baseline responses, report real hits with status and title.
ffuf-lite inside nxc.
"""
import contextlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from nxc.helpers.misc import CATEGORY


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class NXCModule:
    """
    Content discovery: try a wordlist of paths, baseline-diff each
    response so SPA catch-all 200s don't flood the output.

    Output:
        wordlist | http://10.0.0.1/admin/    200 size=4521 (title:Admin)
        wordlist | http://10.0.0.1/.env      403 (auth-protected)
        wordlist | http://10.0.0.1/api/v1    200 size=128

    Required options:
        WORDLIST       Path to a wordlist file (one path per line)

    Other options:
        EXTENSIONS     Comma-separated extensions to also try (e.g. php,bak,zip)
        TIMEOUT        Per-request timeout in seconds. Default: 4
        WORKERS        Concurrent workers. Default: 10
        STATUS         Comma-separated status codes to report. Default: 200,301,302,401,403
        MIN_DIFF_BYTES Min body-size delta vs baseline to treat as a real hit. Default: 64

    Module by @claude
    """

    name = "wordlist"
    description = "Path discovery from a wordlist; baseline-diffed so SPA catch-all 200s don't false-positive"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.wordlist = None
        self.extensions = []
        self.timeout = 4
        self.workers = 10
        self.statuses = {200, 301, 302, 401, 403}
        self.min_diff = 64
        self._seen = set()
        self._lock = threading.Lock()

    def options(self, context, module_options):
        """
        WORDLIST       Path to a wordlist file (REQUIRED)
        EXTENSIONS     Comma-separated extensions (e.g. php,bak,zip)
        TIMEOUT        Per-request timeout. Default: 4
        WORKERS        Concurrent workers. Default: 10
        STATUS         Status codes to report. Default: 200,301,302,401,403
        MIN_DIFF_BYTES Min body-size delta vs baseline. Default: 64
        """
        self.wordlist = module_options.get("WORDLIST")
        ext = module_options.get("EXTENSIONS", "")
        self.extensions = [e.strip().lstrip(".") for e in ext.split(",") if e.strip()]
        self.timeout = int(module_options.get("TIMEOUT", 4))
        self.workers = max(1, int(module_options.get("WORKERS", 10)))
        statuses = module_options.get("STATUS", "")
        if statuses:
            try:
                self.statuses = {int(s.strip()) for s in statuses.split(",") if s.strip()}
            except ValueError:
                context.log.fail(f"STATUS must be a comma-separated list of integers, got {statuses!r}")
        self.min_diff = int(module_options.get("MIN_DIFF_BYTES", 64))

    @staticmethod
    def _extract_title(text):
        if not text:
            return None
        m = _TITLE_RE.search(text)
        if not m:
            return None
        t = re.sub(r"<[^>]+>", "", m.group(1))
        t = " ".join(t.split()).strip()
        return t[:60] or None

    def _load_paths(self):
        if not self.wordlist:
            self.context.log.fail("WORDLIST option is required")
            return []
        try:
            with open(self.wordlist, encoding="utf-8", errors="replace") as f:
                raw = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except OSError as e:
            self.context.log.fail(f"Cannot read wordlist {self.wordlist}: {e}")
            return []
        # Normalize to /path/form and apply extensions.
        out = set()
        for entry in raw:
            p = entry if entry.startswith("/") else "/" + entry
            out.add(p)
            for ext in self.extensions:
                # Only append the extension if the entry doesn't already have one
                # that matches.
                if not p.lower().endswith("." + ext.lower()):
                    out.add(f"{p}.{ext}")
        return sorted(out)

    def _probe(self, connection, path):
        try:
            r, body_bytes, body_text = connection.request_path(path, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"wordlist probe {path}: {e}")
            return
        if r.status_code not in self.statuses:
            return
        if connection.looks_like_baseline(r.status_code, body_bytes):
            return

        # Dedup: if many paths return identical (status, body) — typical of a
        # SPA — collapse them to one report line.
        size = len(body_bytes)
        bucket = size // max(self.min_diff, 1)
        sig = (r.status_code, bucket)
        with self._lock:
            if sig in self._seen and r.status_code != 200:
                return
            # Always emit 200 hits (they're the most actionable), but still
            # dedup later 3xx/4xx that look identical.
            if r.status_code != 200:
                self._seen.add(sig)

        title = self._extract_title(body_text)
        title_part = f" (title:{title})" if title else ""
        url = connection.build_url(path)
        status = r.status_code
        if status == 200:
            self.context.log.highlight(f"{url}  {status} size={size}{title_part}")
        else:
            tag = "auth-protected" if status in (401, 403) else f"size={size}"
            self.context.log.display(f"{url}  {status} {tag}{title_part}")

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session not initialized")
            return

        paths = self._load_paths()
        if not paths:
            return
        context.log.display(f"{connection.host}:{connection.port}  probing {len(paths)} paths from {self.wordlist}")

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = [ex.submit(self._probe, connection, p) for p in paths]
            for f in as_completed(futures):
                with contextlib.suppress(Exception):
                    f.result()
