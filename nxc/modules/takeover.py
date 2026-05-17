"""Subdomain-takeover detection. When a CNAME points at a dangling
SaaS resource, the SaaS returns a known "no such project / bucket / app"
page. This module matches those signatures against the homepage.
"""
import re

from nxc.helpers.misc import CATEGORY


# Patterns from EdOverflow/can-i-take-over-xyz, sanitized for high precision.
# All compiled with IGNORECASE so casing changes in the underlying SaaS error
# pages don't make us miss a takeover signal.
_TAKEOVER_SIGS = [
    (label, re.compile(pattern, re.IGNORECASE)) for label, pattern in [
        ("github-pages", r"There isn't a GitHub Pages site here\.|For root URLs.*pages\.github\.com"),
        ("s3-bucket", r"<Code>NoSuchBucket</Code>|The specified bucket does not exist"),
        ("heroku", r"No such app|herokucdn\.com/error-pages/no-such-app\.html"),
        ("cloudfront", r"Bad request\.\s*ERROR: The request could not be satisfied"),
        ("readme-io", r"Project doesnt exist\.\.\. yet!"),
        ("fastly", r"Fastly error: unknown domain"),
        ("ghost", r"The thing you were looking for is no longer here, or never was"),
        ("pantheon", r"The gods are wise, but do not know of the site which you seek\."),
        ("tumblr", r"Whatever you were looking for doesn't currently exist at this address\."),
        ("wordpress", r"Do you want to register .+\.wordpress\.com\?"),
        ("netlify", r"Not Found - Request ID:"),
        ("shopify", r"Sorry, this shop is currently unavailable\.|<title>Shopify"),
        ("bitbucket", r"Repository not found"),
        ("zendesk", r"Help Center Closed"),
        ("unbounce", r"The requested URL was not found on this server"),
        ("uservoice", r"This UserVoice subdomain is currently available!"),
        ("statuspage", r"You are being <a href=\"https://www\.statuspage\.io"),
        ("acquia", r"Web Site Not Found"),
        ("cargo", r"<title>404 &mdash; File not found"),
        ("intercom", r"This page is reserved for artistic dogs\.|<h1>Uh oh\. That page doesn't exist\.</h1>"),
        ("kinsta", r"No Site For Domain"),
        ("launchrock", r"It looks like you may have taken a wrong turn somewhere\. Don't worry"),
        ("ngrok", r"Tunnel \S+ not found"),
        ("readthedocs", r"unknown to Read the Docs|build a beautiful project for free"),
        ("strikingly", r"PAGE NOT FOUND\."),
        ("surge-sh", r"project not found"),
        ("vend", r"Looks like you've traveled too far into cyberspace\."),
        ("worksites-net", r"Hello! Sorry, but the website you&rsquo;re looking for"),
    ]
]


class NXCModule:
    """
    Subdomain takeover detection. Match the homepage response against
    fingerprints of dangling SaaS resources (GitHub Pages, S3, Heroku,
    Fastly, Shopify, ...).

    Output:
        takeover | http://forgotten.example.com/    [github-pages] possible takeover
        takeover | http://staging.example.com/      [s3-bucket] possible takeover

    Reuses the response the protocol already fetched. Zero extra HTTP
    requests.

    Module by @claude
    """

    name = "takeover"
    description = "Detect subdomain-takeover signatures (GitHub Pages, S3, Heroku, Fastly, Shopify, ...)"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options."""

    def on_login(self, context, connection):
        self.context = context
        body = getattr(connection, "body_text", "")
        if not body:
            return
        url = connection.final_url or connection.url
        hits = []
        for label, pat in _TAKEOVER_SIGS:
            if pat.search(body):
                hits.append(label)
        if hits:
            for label in hits:
                context.log.highlight(f"{url}  [{label}] possible subdomain takeover")
        # No "all clear" line on purpose — would be noise across a /24.
