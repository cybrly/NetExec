"""Probe common API endpoints (Swagger/OpenAPI specs, GraphQL introspection,
versioned REST roots). Extracts endpoint counts when possible so the user
gets actionable output for follow-on testing.
"""
import contextlib
import json
import re

import requests

from nxc.helpers.misc import CATEGORY


SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/api/swagger.json", "/api/openapi.json", "/v1/swagger.json",
    "/swagger-ui/", "/swagger-ui.html", "/api/docs", "/docs",
    "/api-docs", "/api/v2/api-docs",
]

REST_ROOTS = ["/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/", "/api/v3", "/v1", "/v2"]
GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]

_SWAGGER_SIGS = [
    re.compile(r'"swagger"\s*:\s*"[\d.]+"'),
    re.compile(r'"openapi"\s*:\s*"[\d.]+"'),
    re.compile(r'"swaggerVersion"\s*:'),
]
_SWAGGER_UI_SIGS = [
    re.compile(r"swagger-ui", re.IGNORECASE),
    re.compile(r"<title>Swagger UI"),
    re.compile(r"redoc-container"),
]
_GRAPHQL_SIGS = [
    re.compile(r'"__schema"\s*:'),
    re.compile(r'"queryType"\s*:'),
    re.compile(r"<title>.*GraphiQL"),
]
_REST_SIGS = [
    re.compile(r'"paths"\s*:\s*\{'),
    re.compile(r'"resources?"\s*:\s*\['),
    re.compile(r'"_links"\s*:\s*\{'),
]


class NXCModule:
    """
    Probe common API surfaces:
      - Swagger / OpenAPI spec endpoints
      - GraphQL endpoints (incl. introspection POST)
      - Versioned REST roots

    Output:
        api | http://10.0.0.1/swagger.json   200  openapi 3.0 (42 paths)
        api | http://10.0.0.1/graphql        200  GraphQL endpoint (introspection ENABLED, 17 types)
        api | http://10.0.0.1/api/v1         200  REST root

    Options:
        SWAGGER       Probe Swagger/OpenAPI paths. Default: true
        GRAPHQL       Probe GraphQL paths (with introspection POST). Default: true
        REST          Probe versioned REST roots. Default: true

    Module by @claude
    """

    name = "api"
    description = "Probe API surfaces: Swagger/OpenAPI specs, GraphQL endpoints (with introspection), REST roots"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.swagger = True
        self.graphql = True
        self.rest = True

    def options(self, context, module_options):
        """
        SWAGGER  Probe Swagger/OpenAPI paths. Default: true
        GRAPHQL  Probe GraphQL endpoints with introspection. Default: true
        REST     Probe versioned REST roots. Default: true
        """
        self.swagger = module_options.get("SWAGGER", "true").lower() != "false"
        self.graphql = module_options.get("GRAPHQL", "true").lower() != "false"
        self.rest = module_options.get("REST", "true").lower() != "false"

    def _probe_swagger(self, connection, path):
        try:
            r, body_bytes, body_text = connection.request_path(path)
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"swagger probe {path}: {e}")
            return
        if r.status_code != 200:
            return
        if connection.looks_like_baseline(r.status_code, body_bytes):
            return

        url = connection.build_url(path)
        ct = r.headers.get("Content-Type", "").lower()
        if ct.startswith(("application/json", "text/json")) or path.endswith(".json"):
            for sig in _SWAGGER_SIGS:
                if sig.search(body_text):
                    paths_count = self._count_swagger_paths(body_text)
                    extra = f" ({paths_count} paths)" if paths_count is not None else ""
                    self.context.log.highlight(f"{url}  200  Swagger/OpenAPI spec{extra}")
                    return
        # HTML Swagger UI
        for sig in _SWAGGER_UI_SIGS:
            if sig.search(body_text):
                self.context.log.highlight(f"{url}  200  Swagger UI")
                return

    @staticmethod
    def _count_swagger_paths(body_text):
        with contextlib.suppress(Exception):
            data = json.loads(body_text)
            paths = data.get("paths")
            if isinstance(paths, dict):
                return len(paths)
        return None

    def _probe_graphql(self, connection, path):
        url = connection.build_url(path)

        # 1) GET — many GraphQL endpoints return 200 (GraphiQL) or 400 ("must provide query")
        try:
            r, body_bytes, body_text = connection.request_path(path)
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"graphql GET {path}: {e}")
            return
        if connection.looks_like_baseline(r.status_code, body_bytes):
            return

        graphql_hit = False
        if r.status_code in (200, 400, 405):
            for sig in _GRAPHQL_SIGS:
                if sig.search(body_text):
                    graphql_hit = True
                    break
            # 400 with "must provide query" or "query required" is also a strong GraphQL signal
            if not graphql_hit and r.status_code == 400 and re.search(
                r"must provide (a )?query|query (is )?required|query string is required", body_text, re.IGNORECASE,
            ):
                graphql_hit = True

        if not graphql_hit:
            return

        # 2) POST introspection
        introspect = self._introspection_post(connection, path)
        if introspect is None:
            self.context.log.highlight(f"{url}  GraphQL endpoint (introspection state unknown)")
            return
        if introspect:
            types_count = introspect.get("types_count")
            extra = f", {types_count} types" if types_count else ""
            self.context.log.highlight(f"{url}  GraphQL endpoint (introspection ENABLED{extra})")
        else:
            self.context.log.display(f"{url}  GraphQL endpoint (introspection disabled)")

    def _introspection_post(self, connection, path):
        url = connection.build_url(path)
        query = {"query": "{__schema{types{name}}}"}
        try:
            r = connection.session.post(
                url,
                json=query,
                timeout=connection.args.http_timeout,
                allow_redirects=False,
                verify=not connection.args.no_verify,
                stream=True,
            )
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"graphql POST {path}: {e}")
            return None
        # Cap the response so a giant introspection result can't OOM us.
        cap = getattr(connection, "max_body_size", 262144)
        chunks = []
        total = 0
        try:
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                r.close()
        body = b"".join(chunks)[:cap]
        try:
            data = json.loads(body)
            schema = (data.get("data") or {}).get("__schema")
            if not schema:
                return False
            types = schema.get("types") or []
            return {"types_count": len(types)}
        except (ValueError, AttributeError):
            return False

    def _probe_rest(self, connection, path):
        try:
            r, body_bytes, body_text = connection.request_path(path)
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"rest probe {path}: {e}")
            return
        if connection.looks_like_baseline(r.status_code, body_bytes):
            return
        if r.status_code not in (200, 401, 403):
            return
        url = connection.build_url(path)
        # A 401/403 at /api/v1 is itself a strong "API is here" signal
        if r.status_code in (401, 403):
            self.context.log.display(f"{url}  {r.status_code}  REST root (auth-protected)")
            return
        ct = r.headers.get("Content-Type", "").lower()
        if not ct.startswith(("application/json", "text/json", "application/hal")):
            return
        for sig in _REST_SIGS:
            if sig.search(body_text):
                self.context.log.highlight(f"{url}  200  REST root")
                return

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session not initialized")
            return
        if self.swagger:
            for p in SWAGGER_PATHS:
                self._probe_swagger(connection, p)
        if self.graphql:
            for p in GRAPHQL_PATHS:
                self._probe_graphql(connection, p)
        if self.rest:
            for p in REST_ROOTS:
                self._probe_rest(connection, p)
