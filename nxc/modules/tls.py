"""TLS/certificate inspection for HTTPS targets. Dumps subject, issuer,
validity dates, SANs, signature algorithm and flags weak/expired/self-signed
certs.
"""
import contextlib
import socket
import ssl
from datetime import datetime, timezone

from nxc.helpers.misc import CATEGORY


WEAK_SIG_ALGS = {"md5", "sha1"}
EXPIRY_WARN_DAYS = 30


class NXCModule:
    """
    Inspect the TLS certificate on an HTTPS target. Output one block per host:

        tls | 10.0.0.1:443  subject=CN=example.com
        tls | 10.0.0.1:443  issuer=CN=Let's Encrypt R3
        tls | 10.0.0.1:443  valid=2026-01-01 -> 2026-04-01 (days_left=14) [!] expiring soon
        tls | 10.0.0.1:443  sig=sha256WithRSAEncryption
        tls | 10.0.0.1:443  SANs: example.com, www.example.com, api.example.com

    Options:
        TIMEOUT   Socket timeout in seconds. Default: 5
        SUMMARY   Print a one-line summary instead of full details. Default: false

    Module by @claude
    """

    name = "tls"
    description = "Inspect TLS certificate (subject, issuer, expiry, SANs, weak sig algs, self-signed flagging)"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.timeout = 5
        self.summary = False

    def options(self, context, module_options):
        """
        TIMEOUT   Socket timeout in seconds. Default: 5
        SUMMARY   One-line summary instead of full block. Default: false
        """
        self.timeout = int(module_options.get("TIMEOUT", 5))
        self.summary = module_options.get("SUMMARY", "false").lower() == "true"

    def _fetch_cert(self, host, port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=self.timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            version = ssock.version()
        return der, cipher, version

    @staticmethod
    def _name_to_str(name):
        # rfc4514_attribute_name lands in cryptography 41+. Fall back to the
        # OID's friendly name on older versions.
        parts = []
        for a in name:
            attr_name = getattr(a, "rfc4514_attribute_name", None)
            if attr_name is None:
                attr_name = getattr(a.oid, "_name", None) or str(a.oid)
            parts.append(f"{attr_name}={a.value}")
        return ", ".join(parts)

    def on_login(self, context, connection):
        self.context = context
        if not getattr(connection, "is_ssl", False):
            context.log.display(f"{connection.host}:{connection.port}  not HTTPS — skipping (use --ssl or an HTTPS port)")
            return

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            context.log.fail("python 'cryptography' package not installed; cannot decode cert")
            return

        try:
            der, cipher, version = self._fetch_cert(connection.host, connection.port)
        except (TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
            context.log.fail(f"{connection.host}:{connection.port}  TLS handshake failed: {e}")
            return

        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
        except Exception as e:
            context.log.fail(f"{connection.host}:{connection.port}  cert decode failed: {e}")
            return

        host_port = f"{connection.host}:{connection.port}"
        subject = self._name_to_str(cert.subject)
        issuer = self._name_to_str(cert.issuer)
        # cryptography 42+ deprecates not_valid_before in favour of *_utc
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
        self_signed = cert.issuer == cert.subject

        sans = []
        with contextlib.suppress(x509.ExtensionNotFound):
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(n.value) for n in ext.value]

        # Build status flags
        flags = []
        if now > not_after:
            flags.append("EXPIRED")
        elif days_left < EXPIRY_WARN_DAYS:
            flags.append(f"expiring in {days_left}d")
        if now < not_before:
            flags.append("not-yet-valid")
        if self_signed:
            flags.append("self-signed")
        if sig_alg.lower() in WEAK_SIG_ALGS:
            flags.append(f"weak-sig:{sig_alg}")
        flag_str = "  [!] " + ", ".join(flags) if flags else ""

        cipher_name = cipher[0] if cipher else "?"

        if self.summary:
            tls_v = version or "?"
            line = f"{host_port}  CN={subject.split('CN=', 1)[-1].split(',')[0] if 'CN=' in subject else subject}  {tls_v}  {cipher_name}  days_left={days_left}{flag_str}"
            (context.log.highlight if flags else context.log.display)(line)
            return

        context.log.display(f"{host_port}  subject={subject}")
        context.log.display(f"{host_port}  issuer={issuer}")
        valid_line = f"{host_port}  valid={not_before:%Y-%m-%d} -> {not_after:%Y-%m-%d} (days_left={days_left}){flag_str}"
        (context.log.highlight if flags else context.log.display)(valid_line)
        context.log.display(f"{host_port}  sig={sig_alg}  tls={version or '?'}  cipher={cipher_name}")
        if sans:
            context.log.display(f"{host_port}  SANs: {', '.join(sans[:10])}{' ...' if len(sans) > 10 else ''}")
