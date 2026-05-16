"""Audit HTTP security headers on the target's homepage. Reports missing
headers and weak values.
"""
from nxc.helpers.misc import CATEGORY


SECURITY_HEADERS = [
    ("Strict-Transport-Security", lambda v: "max-age=" in v.lower(), "missing HSTS — set max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", None, "missing CSP — set a restrictive policy"),
    ("X-Frame-Options", lambda v: v.strip().lower() in ("deny", "sameorigin"), "missing/weak X-Frame-Options — set DENY or SAMEORIGIN"),
    ("X-Content-Type-Options", lambda v: v.strip().lower() == "nosniff", "missing X-Content-Type-Options — set nosniff"),
    ("Referrer-Policy", None, "missing Referrer-Policy"),
    ("Permissions-Policy", None, "missing Permissions-Policy"),
    ("X-XSS-Protection", lambda v: "0" in v or "1" in v, "X-XSS-Protection is deprecated but if present should be 0"),
]


class NXCModule:
    """
    Audit HTTP security headers on the target's homepage. Output:

        headers | https://10.0.0.1/    missing: HSTS, CSP, X-Frame-Options
        headers | https://10.0.0.2/    all present

    Reuses the homepage response the protocol already fetched, so no
    extra HTTP request. Combine with --quiet for clean subnet scans.

    Options:
        VERBOSE  Print the value of each present header. Default: false

    Module by @claude
    """

    name = "headers"
    description = "Audit HTTP security headers (HSTS, CSP, X-Frame-Options, ...)"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.verbose = False

    def options(self, context, module_options):
        """VERBOSE  Print the value of each present header. Default: false"""
        self.verbose = module_options.get("VERBOSE", "false").lower() == "true"

    def on_login(self, context, connection):
        response = getattr(connection, "response", None)
        if response is None:
            context.log.fail("No response captured — protocol probe must succeed first")
            return

        headers = response.headers
        missing = []
        weak = []
        present = []

        for name, validator, advice in SECURITY_HEADERS:
            value = headers.get(name)
            if value is None:
                missing.append((name, advice))
                continue
            if validator is not None and not validator(value):
                weak.append((name, value, advice))
            else:
                present.append((name, value))

        url = connection.final_url or connection.url
        if missing:
            for name, advice in missing:
                context.log.highlight(f"{url}  [-] {name}: {advice}")
        for name, value, advice in weak:
            context.log.highlight(f"{url}  [~] {name}={value}: {advice}")
        if self.verbose:
            for name, value in present:
                context.log.display(f"{url}  [+] {name}: {value}")
        if not missing and not weak:
            context.log.success(f"{url}  all audited security headers present")
