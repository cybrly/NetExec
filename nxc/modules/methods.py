"""Probe allowed HTTP methods via OPTIONS. Flags dangerous methods
(PUT, DELETE, TRACE, CONNECT) if exposed.
"""
import contextlib

import requests

from nxc.helpers.misc import CATEGORY


DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


class NXCModule:
    """
    Probe allowed HTTP methods via OPTIONS. Output:

        methods | http://10.0.0.1/    allowed: GET, HEAD, POST, OPTIONS
        methods | http://10.0.0.2/    allowed: GET, POST, PUT, DELETE  [!] dangerous: PUT, DELETE

    Options:
        PATH  Path to send OPTIONS against. Default: --path from the protocol

    Module by @claude
    """

    name = "methods"
    description = "Probe allowed HTTP methods via OPTIONS and flag dangerous ones (PUT, DELETE, TRACE, ...)"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.path = None

    def options(self, context, module_options):
        """PATH  Path to send OPTIONS against. Default: protocol --path"""
        self.path = module_options.get("PATH")

    def on_login(self, context, connection):
        path = self.path or connection.args.path
        url = connection.build_url(path)
        try:
            r = connection.session.options(
                url,
                timeout=connection.args.http_timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            context.log.fail(f"{url}: OPTIONS failed: {e}")
            return

        allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods")
        if not allow:
            context.log.display(f"{url}: server didn't return Allow header (HTTP {r.status_code})")
            return

        methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
        dangerous = sorted(set(methods) & DANGEROUS_METHODS)
        line = f"{url}  allowed: {', '.join(methods)}"
        if dangerous:
            context.log.highlight(f"{line}  [!] dangerous: {', '.join(dangerous)}")
        else:
            context.log.display(line)
        # Read and drop any body so the connection can be reused.
        with contextlib.suppress(Exception):
            r.close()
