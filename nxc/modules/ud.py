"""Compact technology-stack output for HTTP scans."""
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Underlying-technologies output. Prints one line per host:

        ud | 10.0.0.1:80    nginx,php,wordpress
        ud | 10.0.0.2:443   apache,asp.net
        ud | 10.0.0.3:80    (none detected)

    Reuses the fingerprints already computed by the protocol, so this is
    free — no extra HTTP requests. Combine with --quiet to suppress the
    default verbose line.

    Module by @claude
    """

    name = "ud"
    description = "Compact underlying-tech output (nginx,php,wordpress,...). Use with --quiet for clean subnet scans"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options."""

    def on_login(self, context, connection):
        techs = getattr(connection, "technologies", []) or []
        server = (getattr(connection, "server", None) or "").strip()
        host_port = f"{connection.host}:{connection.port}"
        if techs:
            tech_str = ",".join(techs)
        elif server:
            tech_str = f"server-only:{server.split(' ', 1)[0]}"
        else:
            tech_str = "(none detected)"
        context.log.highlight(f"{host_port:<22} {tech_str}")
