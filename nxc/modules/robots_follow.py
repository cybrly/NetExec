"""Fetch /robots.txt, parse Disallow: entries, probe each one.
Admins tend to Disallow paths they want to hide — high-signal targets.
"""
import contextlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from nxc.helpers.misc import CATEGORY


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DISALLOW_RE = re.compile(r"^\s*Disallow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_ALLOW_RE = re.compile(r"^\s*Allow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SITEMAP_RE = re.compile(r"^\s*Sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


class NXCModule:
    """
    Parse robots.txt and probe each Disallow entry. Useful for finding
    paths the admin tried to hide from crawlers.

    Output:
        robots | http://10.0.0.1/robots.txt   parsed 12 disallow entries
        robots | http://10.0.0.1/admin/       200 size=4521 (title:Admin)
        robots | http://10.0.0.1/backup/      403 (auth-protected)
        robots | http://10.0.0.1/sitemap.xml  declared sitemap

    Options:
        TIMEOUT   Per-request timeout in seconds. Default: 4
        WORKERS   Concurrent probes. Default: 5
        INCLUDE_ALLOW   Also probe Allow: entries (default false — they're
                        usually less interesting)

    Module by @claude
    """

    name = "robots_follow"
    description = "Parse robots.txt and probe each Disallow entry — finds paths the admin tried to hide"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.timeout = 4
        self.workers = 5
        self.include_allow = False

    def options(self, context, module_options):
        """
        TIMEOUT          Per-request timeout. Default: 4
        WORKERS          Concurrent probes. Default: 5
        INCLUDE_ALLOW    Also probe Allow: entries. Default: false
        """
        self.timeout = int(module_options.get("TIMEOUT", 4))
        self.workers = max(1, int(module_options.get("WORKERS", 5)))
        self.include_allow = module_options.get("INCLUDE_ALLOW", "false").lower() == "true"

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

    def _probe(self, connection, path):
        # robots.txt entries can be patterns like "/admin/*" or "/?param=" —
        # strip wildcards/query-only patterns since they aren't navigable URLs.
        clean = path.split("*", 1)[0].split("?", 1)[0]
        if not clean or clean == "/":
            return
        try:
            r, body_bytes, body_text = connection.request_path(clean, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"robots probe {clean}: {e}")
            return
        if connection.looks_like_baseline(r.status_code, body_bytes):
            return
        if r.status_code == 404:
            return
        url = connection.build_url(clean)
        title = self._extract_title(body_text)
        title_part = f" (title:{title})" if title else ""
        if r.status_code in (401, 403):
            self.context.log.display(f"{url}  {r.status_code} (auth-protected){title_part}")
        elif r.status_code == 200:
            self.context.log.highlight(f"{url}  200 size={len(body_bytes)}{title_part}")
        elif 300 <= r.status_code < 400:
            location = r.headers.get("Location", "")
            self.context.log.display(f"{url}  {r.status_code} -> {location}")
        else:
            self.context.log.display(f"{url}  {r.status_code} size={len(body_bytes)}")

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session not initialized")
            return

        try:
            r, body_bytes, body_text = connection.request_path("/robots.txt", timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            context.log.fail(f"robots.txt fetch failed: {e}")
            return
        if r.status_code != 200:
            context.log.display(f"{connection.build_url('/robots.txt')}  HTTP {r.status_code} — no robots.txt")
            return
        if "text/plain" not in r.headers.get("Content-Type", "").lower() and "<html" in body_text.lower():
            # Some sites return an HTML 404-ish page with 200 status for unknown paths.
            context.log.display(f"{connection.build_url('/robots.txt')}  responded but content looks like HTML; skipping")
            return

        disallows = _DISALLOW_RE.findall(body_text)
        allows = _ALLOW_RE.findall(body_text) if self.include_allow else []
        sitemaps = _SITEMAP_RE.findall(body_text)

        url = connection.build_url("/robots.txt")
        context.log.display(f"{url}  parsed {len(disallows)} disallow, {len(allows)} allow, {len(sitemaps)} sitemap entries")

        for sm in sitemaps:
            context.log.display(f"{connection.host}:{connection.port}  declared sitemap: {sm}")

        targets = sorted(set(disallows + allows))
        if not targets:
            return

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = [ex.submit(self._probe, connection, t) for t in targets]
            for f in as_completed(futures):
                with contextlib.suppress(Exception):
                    f.result()
