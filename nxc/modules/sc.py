"""Compact status-code output for HTTP scans. Pairs well with --quiet for
clean one-line-per-host output across a subnet.
"""
from nxc.helpers.misc import CATEGORY


_STATUS_REASONS = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 418: "I'm a teapot", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
}


class NXCModule:
    """
    Status-code-only output. Prints one line per host:

        sc | 10.0.0.1:80    301  Moved Permanently
        sc | 10.0.0.2:80    200  OK

    Combine with --quiet to suppress the default verbose line.

    Module by @claude
    """

    name = "sc"
    description = "Compact status-code-only output (use with --quiet for clean subnet scans)"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options."""

    def on_login(self, context, connection):
        status = connection.status_code
        if status is None:
            return
        reason = _STATUS_REASONS.get(status, "")
        host_port = f"{connection.host}:{connection.port}"
        line = f"{host_port:<22} {status}  {reason}".rstrip()
        context.log.highlight(line)
