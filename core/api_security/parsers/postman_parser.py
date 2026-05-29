"""Postman Collection v2.1 parser.

Translates Postman's request-centric model into our endpoint-centric APISpec.
Resolves Postman variables (e.g., {{baseUrl}}) from the collection's variable block.
"""

import re

from core.api_security.exceptions import SpecParseError, UnsupportedSpecError
from core.api_security.models import (
    APISpec,
    AuthSpec,
    AuthType,
    Endpoint,
    HTTPMethod,
    Parameter,
    ParameterLocation,
    RequestBody,
    SchemaSpec,
    SpecFormat,
)
from core.api_security.parsers.base import SpecParser
from core.logging_config import get_logger

logger = get_logger("postman_parser")

POSTMAN_VAR_PATTERN = re.compile(r"\{\{([^}]+)\}\}")
POSTMAN_PATH_PARAM_PATTERN = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)")


class PostmanParser(SpecParser):
    """Parser for Postman Collection v2.1 files."""

    name = "postman"
    supported_formats = ("json",)

    EXPECTED_SCHEMA_FRAGMENT = "v2.1.0/collection.json"

    def can_parse(self, content: dict | str | bytes) -> bool:
        try:
            data = self._ensure_dict(content)
        except Exception:
            return False
        info = data.get("info", {})
        schema = info.get("schema", "")
        return self.EXPECTED_SCHEMA_FRAGMENT in schema

    def parse(self, content: dict | str | bytes) -> APISpec:
        self._warnings = []
        data = self._ensure_dict(content)
        info = data.get("info", {})

        schema = info.get("schema", "")
        if self.EXPECTED_SCHEMA_FRAGMENT not in schema:
            raise UnsupportedSpecError(
                f"Not a Postman Collection v2.1 file (schema: {schema!r})"
            )

        # Validate basic structure
        if "info" not in data:
            if not self.lenient:
                raise SpecParseError("Postman collection missing 'info' block")
            self._add_warning("MISSING_INFO", "No info block found")
        if "item" not in data:
            if not self.lenient:
                raise SpecParseError("Postman collection missing 'item' block")
            self._add_warning("MISSING_ITEM", "No item block found")

        # Resolve collection-level variables
        variables = self._extract_variables(data.get("variable", []))

        # Resolve collection-level auth (applies to all items unless overridden)
        collection_auth = self._parse_auth(data.get("auth"))

        # Walk items (Postman supports nested folders)
        items = data.get("item", [])
        endpoints = []
        for item in items:
            endpoints.extend(self._walk_item(item, variables, collection_auth))

        # Determine base URL from first endpoint or variables
        base_url = self._infer_base_url(variables, endpoints)

        # Build auth_schemes dict
        auth_schemes = {}
        if collection_auth and collection_auth.type != AuthType.NONE:
            auth_schemes["default"] = collection_auth

        return APISpec(
            name=info.get("name", "Postman Collection"),
            version=info.get("version", "unknown"),
            description=info.get("description"),
            source_format=SpecFormat.POSTMAN_2_1,
            base_url=base_url,
            auth_schemes=auth_schemes,
            endpoints=endpoints,
            warnings=list(self._warnings),
            metadata={
                "postman_id": info.get("_postman_id"),
                "endpoint_count": len(endpoints),
            },
        )

    # ---------- Variables ----------

    def _extract_variables(self, variables: list) -> dict[str, str]:
        result = {}
        for v in variables:
            key = v.get("key")
            value = v.get("value", "")
            if key:
                result[key] = str(value)
        return result

    def _resolve_variables(self, text: str, variables: dict[str, str]) -> str:
        """Replace {{var}} with variable values. Unknown vars left as-is + warning."""

        def replace(match):
            name = match.group(1).strip()
            if name in variables:
                return variables[name]
            self._add_warning(
                "UNRESOLVED_VARIABLE",
                f"Postman variable {{{{{name}}}}} not found in collection variables",
            )
            return match.group(0)

        return POSTMAN_VAR_PATTERN.sub(replace, text)

    # ---------- Item walking (recursive for folders) ----------

    def _walk_item(
        self,
        item: dict,
        variables: dict[str, str],
        collection_auth: AuthSpec | None,
    ) -> list[Endpoint]:
        endpoints = []
        if "item" in item:  # folder
            for child in item["item"]:
                endpoints.extend(self._walk_item(child, variables, collection_auth))
        elif "request" in item:  # request
            ep = self._parse_request_item(item, variables, collection_auth)
            if ep:
                endpoints.append(ep)
        return endpoints

    def _parse_request_item(
        self,
        item: dict,
        variables: dict[str, str],
        collection_auth: AuthSpec | None,
    ) -> Endpoint | None:
        request = item.get("request", {})
        if not isinstance(request, dict):
            self._add_warning(
                "INVALID_REQUEST",
                f"Item '{item.get('name', '?')}' has invalid request block",
            )
            return None

        # Method
        method_str = request.get("method", "GET").upper()
        try:
            method = HTTPMethod(method_str)
        except ValueError:
            self._add_warning("INVALID_METHOD", f"Unknown HTTP method: {method_str}")
            return None

        # URL → path
        url_block = request.get("url", {})
        if isinstance(url_block, str):
            url_block = {"raw": url_block}

        raw_url = url_block.get("raw", "")
        raw_url_resolved = self._resolve_variables(raw_url, variables)

        # Parse out path (everything after host)
        path = self._extract_path(url_block, variables)

        # Path parameters: detect :param and {param}
        path_params = self._extract_path_params(path, url_block, variables)

        # Query parameters
        query_params = []
        for q in url_block.get("query", []):
            if not isinstance(q, dict):
                continue
            query_params.append(
                Parameter(
                    name=q.get("key", ""),
                    location=ParameterLocation.QUERY,
                    required=not q.get("disabled", False),
                    example=q.get("value"),
                    description=q.get("description"),
                )
            )

        # Headers
        header_params = []
        for h in request.get("header", []):
            if not isinstance(h, dict):
                continue
            key = h.get("key", "")
            if key.lower() == "authorization":
                continue  # don't expose auth headers as params
            header_params.append(
                Parameter(
                    name=key,
                    location=ParameterLocation.HEADER,
                    required=not h.get("disabled", False),
                    example=h.get("value"),
                )
            )

        # Body
        request_body = None
        body = request.get("body")
        if body:
            request_body = self._parse_body(body)

        # Auth (request-level overrides collection-level)
        request_auth = self._parse_auth(request.get("auth"))
        effective_auth = (
            request_auth
            if request_auth and request_auth.type != AuthType.NONE
            else collection_auth
        )

        # Build security requirement if auth exists
        security = []
        if effective_auth and effective_auth.type != AuthType.NONE:
            from core.api_security.models import SecurityRequirement

            security.append(SecurityRequirement(scheme_name="default"))

        return Endpoint(
            path=path,
            method=method,
            operation_id=item.get("name"),
            summary=item.get("name"),
            description=item.get("description"),
            parameters=path_params + query_params + header_params,
            request_body=request_body,
            security=security,
            source_metadata={
                "postman_name": item.get("name"),
                "raw_url": raw_url_resolved,
            },
        )

    # ---------- Path extraction ----------

    def _extract_path(self, url_block: dict, variables: dict[str, str]) -> str:
        """Extract the path portion of a Postman URL.

        Postman URLs can be:
        - A `path` list: ["pets", ":petId"] → "/pets/{petId}"
        - A `raw` URL: "https://api/pets/:petId" → "/pets/{petId}"
        """
        path_parts = url_block.get("path", [])
        if path_parts:
            normalized = []
            for part in path_parts:
                if not isinstance(part, str):
                    continue
                resolved = self._resolve_variables(part, variables)
                # Convert :param to {param}
                resolved = POSTMAN_PATH_PARAM_PATTERN.sub(r"{\1}", resolved)
                normalized.append(resolved)
            return "/" + "/".join(normalized)

        # Fall back to parsing raw URL
        raw = self._resolve_variables(url_block.get("raw", ""), variables)
        if not raw:
            return "/"

        from urllib.parse import urlparse

        parsed = urlparse(raw)
        path = parsed.path or "/"
        # Convert :param style to {param}
        path = POSTMAN_PATH_PARAM_PATTERN.sub(r"{\1}", path)
        return path or "/"

    def _extract_path_params(
        self, path: str, url_block: dict, variables: dict[str, str]
    ) -> list[Parameter]:
        """Detect {param} placeholders in path and create Parameter entries."""
        params = []
        for match in re.finditer(r"\{([^}]+)\}", path):
            name = match.group(1)
            # Look up example in url.variable block
            example = None
            for var in url_block.get("variable", []):
                if isinstance(var, dict) and var.get("key") == name:
                    example = var.get("value")
                    break
            params.append(
                Parameter(
                    name=name,
                    location=ParameterLocation.PATH,
                    required=True,
                    example=example,
                )
            )
        return params

    # ---------- Body ----------

    def _parse_body(self, body: dict) -> RequestBody | None:
        if not isinstance(body, dict):
            return None
        mode = body.get("mode")
        if mode == "raw":
            raw_content = body.get("raw", "")
            content_type = "application/json"
            options = body.get("options", {})
            if isinstance(options, dict):
                raw_opts = options.get("raw", {})
                lang = raw_opts.get("language", "")
                if lang == "json":
                    content_type = "application/json"
                elif lang == "xml":
                    content_type = "application/xml"
                elif lang == "text":
                    content_type = "text/plain"
            return RequestBody(
                required=True,
                content_type=content_type,
                schema=SchemaSpec(raw={"example": raw_content}),
                example=raw_content,
            )
        if mode == "formdata":
            return RequestBody(
                required=True,
                content_type="multipart/form-data",
                schema=SchemaSpec(type="object"),
            )
        if mode == "urlencoded":
            return RequestBody(
                required=True,
                content_type="application/x-www-form-urlencoded",
                schema=SchemaSpec(type="object"),
            )
        return None

    # ---------- Auth ----------

    def _parse_auth(self, auth: dict | None) -> AuthSpec | None:
        if not auth or not isinstance(auth, dict):
            return None
        auth_type_str = auth.get("type", "").lower()
        type_map = {
            "bearer": AuthType.BEARER,
            "basic": AuthType.BASIC,
            "apikey": AuthType.API_KEY,
            "oauth2": AuthType.OAUTH2,
            "noauth": AuthType.NONE,
        }
        auth_type = type_map.get(auth_type_str, AuthType.UNKNOWN)
        return AuthSpec(type=auth_type, description=f"Postman auth: {auth_type_str}")

    # ---------- Base URL inference ----------

    def _infer_base_url(
        self, variables: dict[str, str], endpoints: list[Endpoint]
    ) -> str:
        # Prefer common variable names
        for key in ("baseUrl", "base_url", "host", "url"):
            if key in variables:
                return variables[key]
        # Fall back to extracting from first endpoint's raw URL
        if endpoints:
            raw = endpoints[0].source_metadata.get("raw_url", "")
            if raw:
                from urllib.parse import urlparse

                parsed = urlparse(raw)
                if parsed.scheme and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
        return ""
