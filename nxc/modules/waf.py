"""WAF/CDN detection via response headers, cookies, and body patterns.
Useful to know when your probes are getting filtered.
"""
import re

from nxc.helpers.misc import CATEGORY


# Each entry: (label, list of (location, regex) tuples)
# location is "header:<name>", "cookie:<name>", or "body"
_WAF_SIGNATURES = [
    ("cloudflare", [
        ("header:server", re.compile(r"cloudflare", re.IGNORECASE)),
        ("header:cf-ray", re.compile(r".+")),
        ("cookie:__cfduid", re.compile(r".+")),
        ("cookie:__cf_bm", re.compile(r".+")),
        ("body", re.compile(r"Attention Required! \| Cloudflare|cdn-cgi/")),
    ]),
    ("aws-cloudfront", [
        ("header:x-amz-cf-id", re.compile(r".+")),
        ("header:via", re.compile(r"cloudfront", re.IGNORECASE)),
    ]),
    ("akamai", [
        ("header:server", re.compile(r"AkamaiGHost", re.IGNORECASE)),
        ("header:x-akamai-transformed", re.compile(r".+")),
        ("body", re.compile(r"Reference&#32;&#35;\d+\.|akamai\.com")),
    ]),
    ("aws-waf", [
        ("header:x-amzn-requestid", re.compile(r".+")),
        ("header:x-amz-waf", re.compile(r".+")),
        ("body", re.compile(r"AWS WAF|aws-waf-token")),
    ]),
    ("imperva-incapsula", [
        ("header:x-iinfo", re.compile(r".+")),
        ("cookie:visid_incap_", re.compile(r".+")),
        ("cookie:incap_ses_", re.compile(r".+")),
        ("body", re.compile(r"Incapsula incident ID")),
    ]),
    ("f5-bigip", [
        ("header:server", re.compile(r"BigIP|BIG-IP", re.IGNORECASE)),
        ("cookie:bigipserver", re.compile(r".+")),
        ("cookie:f5_cspm", re.compile(r".+")),
    ]),
    ("sucuri", [
        ("header:server", re.compile(r"sucuri", re.IGNORECASE)),
        ("header:x-sucuri-id", re.compile(r".+")),
        ("body", re.compile(r"Access Denied - Sucuri Website Firewall")),
    ]),
    ("fastly", [
        ("header:x-served-by", re.compile(r"cache-[a-z]{3}\d+", re.IGNORECASE)),
        ("header:fastly-debug-digest", re.compile(r".+")),
        ("header:server", re.compile(r"\bfastly\b", re.IGNORECASE)),
    ]),
    ("azure-frontdoor", [
        ("header:x-azure-ref", re.compile(r".+")),
    ]),
    ("google-cloud-load-balancer", [
        ("header:server", re.compile(r"^Google Frontend$|^GFE/", re.IGNORECASE)),
    ]),
    ("cloudfront", [
        ("header:via", re.compile(r"CloudFront", re.IGNORECASE)),
    ]),
    ("modsecurity", [
        ("header:server", re.compile(r"mod_security|modsecurity", re.IGNORECASE)),
        ("body", re.compile(r"Mod_Security|NOYB")),
    ]),
    ("varnish", [
        ("header:via", re.compile(r"varnish", re.IGNORECASE)),
        ("header:x-varnish", re.compile(r".+")),
    ]),
    ("fortinet", [
        ("cookie:FORTIWAFSID", re.compile(r".+")),
        ("body", re.compile(r"FortiWeb|FortiGate")),
    ]),
    ("barracuda", [
        ("cookie:barra_counter_session", re.compile(r".+")),
        ("body", re.compile(r"Barracuda WAF|barra_counter")),
    ]),
    ("citrix-netscaler", [
        ("header:via", re.compile(r"NS-CACHE", re.IGNORECASE)),
        ("cookie:citrix_ns_id", re.compile(r".+")),
    ]),
]


class NXCModule:
    """
    Detect WAFs and CDNs from the homepage response we already fetched.
    Reuses the existing protocol response — zero extra HTTP requests.

    Output:
        waf | http://10.0.0.1/    [cloudflare] header:cf-ray
        waf | http://10.0.0.1/    [aws-cloudfront] header:via

    Module by @claude
    """

    name = "waf"
    description = "Detect WAFs and CDNs (Cloudflare, Akamai, AWS WAF, Imperva, F5, Fastly, ...)"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options."""

    def on_login(self, context, connection):
        self.context = context
        response = getattr(connection, "response", None)
        if response is None:
            context.log.fail("No response captured")
            return

        url = connection.final_url or connection.url
        # Build (lowercase-keyed) maps once.
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        cookies_blob = response.headers.get("Set-Cookie", "")
        cookie_names = " ".join(c.name for c in response.cookies)
        body = getattr(connection, "body_text", "")[:65536]

        for label, sigs in _WAF_SIGNATURES:
            for loc, pat in sigs:
                if loc.startswith("header:"):
                    hname = loc.split(":", 1)[1]
                    hval = headers_lower.get(hname.lower())
                    if hval and pat.search(hval):
                        context.log.highlight(f"{url}  [{label}]  matched {loc}")
                        break  # one match per WAF is enough
                elif loc.startswith("cookie:"):
                    cname = loc.split(":", 1)[1]
                    cookie_haystack = f"{cookies_blob} {cookie_names}"
                    # Require the cookie name itself to be present so we don't
                    # false-positive on body content the pattern happens to hit.
                    if pat.search(cookie_haystack) and cname.lower() in cookie_haystack.lower():
                        context.log.highlight(f"{url}  [{label}]  matched {loc}")
                        break
                elif loc == "body":
                    if pat.search(body):
                        context.log.highlight(f"{url}  [{label}]  matched body")
                        break
