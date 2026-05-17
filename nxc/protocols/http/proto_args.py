from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    http_parser = parser.add_parser("http", help="own stuff using HTTP/HTTPS", parents=parents, formatter_class=DisplayDefaultsNotNone)
    http_parser.add_argument("--port", type=int, default=80, help="HTTP(S) port")
    http_parser.add_argument("--ssl", action="store_true", help="Force HTTPS (auto-enabled for ports 443, 8443, 4443, 9443)")
    http_parser.add_argument("--no-verify", action="store_true", help="Do not verify TLS certificates")
    http_parser.add_argument("--path", default="/", help="Request path to probe for service/title")
    http_parser.add_argument("--user-agent", default=None, help="Custom User-Agent string")
    http_parser.add_argument("--http-timeout", type=int, default=10, help="HTTP request timeout in seconds")
    http_parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects when probing")
    http_parser.add_argument("--proxy", default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")
    http_parser.add_argument("--max-body-size", type=int, default=262144, help="Maximum response body bytes to read (anti-DoS)")
    http_parser.add_argument("--quiet", action="store_true", help="Suppress the default per-host info line — useful for subnet scans where you only want module output")
    http_parser.add_argument("--auto-scheme", action="store_true", help="Try the other scheme (HTTP/HTTPS) if the first connection fails")
    http_parser.add_argument("--no-favicon", action="store_true", help="Skip the favicon hash fingerprint")
    http_parser.add_argument("--output-format", choices=["text", "json", "csv"], default="text", help="Per-host output format")

    egroup = http_parser.add_argument_group("HTTP", "HTTP Probing")
    egroup.add_argument("--auth-type", choices=["basic", "digest", "ntlm"], default="basic", help="HTTP authentication scheme to use when credentials are supplied")
    egroup.add_argument("--check-auth-path", default=None, help="Override the path used to validate HTTP credentials (defaults to --path)")

    fgroup = http_parser.add_argument_group("HTTP Form Auth", "Validate form-/cookie-based logins when HTTP Basic isn't in use")
    fgroup.add_argument("--form-login-url", default=None, help="Login form endpoint (POST target). When set, credentials are validated via form auth instead of HTTP Basic")
    fgroup.add_argument("--form-user-field", default="username", help="Form field name for the username")
    fgroup.add_argument("--form-pass-field", default="password", help="Form field name for the password")
    fgroup.add_argument("--form-success", default=None, help="Regex matched against the login response — match means success")
    fgroup.add_argument("--form-fail", default=None, help="Regex matched against the login response — match means failure (used when --form-success isn't provided; defaults to common 'invalid credentials' strings)")
    fgroup.add_argument("--form-extra", nargs="*", default=[], help="Extra form fields as KEY=VALUE pairs (e.g. csrf_token=ABCD123)")

    return parser
