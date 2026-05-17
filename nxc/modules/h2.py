"""HTTP/2 (and HTTP/3 hint) detection via TLS ALPN. Connects with raw ssl,
offers h2/http/1.1 in the ALPN list, reports what the server picks. Cheap
and reliable — doesn't need an HTTP/2 client library.
"""
import socket
import ssl

from nxc.helpers.misc import CATEGORY


# Headers a server uses to advertise HTTP/3 endpoints.
_ALT_SVC_HINT = ("alt-svc", "Alt-Svc")


class NXCModule:
    """
    Detect HTTP/2 (and HTTP/3 hints) on HTTPS targets.

    HTTP/2 detection uses TLS ALPN: we offer the ALPN protocol list
    [h2, http/1.1] in the handshake and report what the server selected.

    HTTP/3 detection uses the Alt-Svc header the protocol already saw.

    Output:
        h2 | 10.0.0.1:443  ALPN=h2  (HTTP/2 enabled)
        h2 | 10.0.0.1:443  ALPN=http/1.1  (HTTP/2 not advertised)
        h2 | 10.0.0.1:443  Alt-Svc: h3=":443"  (HTTP/3 advertised)

    Options:
        TIMEOUT   Socket timeout in seconds. Default: 5

    Module by @claude
    """

    name = "h2"
    description = "Detect HTTP/2 via TLS ALPN; report HTTP/3 Alt-Svc advertisement"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.timeout = 5

    def options(self, context, module_options):
        """TIMEOUT  Socket timeout. Default: 5"""
        self.timeout = int(module_options.get("TIMEOUT", 5))

    # Sentinel return codes so we can tell three failure modes apart from
    # "server picked ALPN X" (which can include None when the server simply
    # didn't choose anything).
    _ALPN_UNSUPPORTED = "__unsupported__"
    _ALPN_HANDSHAKE_FAILED = "__handshake_failed__"

    def _alpn_probe(self, host, port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            return self._ALPN_UNSUPPORTED
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.selected_alpn_protocol()  # may be None or a string
        except (TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
            self.context.log.debug(f"ALPN probe failed: {e}")
            return self._ALPN_HANDSHAKE_FAILED

    def on_login(self, context, connection):
        self.context = context
        host_port = f"{connection.host}:{connection.port}"

        if not getattr(connection, "is_ssl", False):
            context.log.display(f"{host_port}  HTTP/2 negotiation requires TLS — skipping (use --ssl)")
            return

        alpn = self._alpn_probe(connection.host, connection.port)
        if alpn == self._ALPN_UNSUPPORTED:
            context.log.fail(f"{host_port}  ALPN not supported by this Python/OpenSSL build")
        elif alpn == self._ALPN_HANDSHAKE_FAILED:
            context.log.fail(f"{host_port}  TLS handshake failed during ALPN probe")
        elif alpn == "h2":
            context.log.highlight(f"{host_port}  ALPN=h2  (HTTP/2 enabled)")
        elif alpn is None:
            context.log.display(f"{host_port}  no ALPN selected (server didn't pick a protocol)")
        else:
            context.log.display(f"{host_port}  ALPN={alpn}  (HTTP/2 not advertised)")

        # HTTP/3 hint from Alt-Svc on the homepage response
        response = getattr(connection, "response", None)
        if response is not None:
            alt_svc = response.headers.get("Alt-Svc") or response.headers.get("alt-svc")
            if alt_svc and ("h3" in alt_svc.lower() or "quic" in alt_svc.lower()):
                context.log.highlight(f"{host_port}  Alt-Svc: {alt_svc}  (HTTP/3 advertised)")
