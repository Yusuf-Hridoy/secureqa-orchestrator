"""OpenAPI 3.0 + 3.1 parser.

Converts OpenAPI specs (JSON or YAML) into the normalized APISpec model.
Handles internal $ref resolution. External $ref URLs are NOT fetched
(security-conservative — avoids SSRF in our own tool).
"""

from typing import Any

from core.api_security.exceptions import (
    SpecParseError,
    UnresolvedRefError,
    UnsupportedSpecError,
)
from core.api_security.models import (
    APISpec,
    AuthSpec,
    AuthType,
    Endpoint,
    HTTPMethod,
    Parameter,
    ParameterLocation,
    RequestBody,
    Response,
    SchemaSpec,
    SecurityRequirement,
    SpecFormat,
)
from core.api_security.parsers.base import SpecParser
from core.logging_config import get_logger

logger = get_logger("openapi_parser")


class OpenAPIParser(SpecParser):
    """Parser for OpenAPI 3.0 and 3.1 specifications."""

    name = "openapi"
    supported_formats = ("json", "yaml")

    SUPPORTED_VERSIONS = ("3.0", "3.1")

    def can_parse(self, content: dict | str | bytes) -> bool:
        """Return True if content looks like an OpenAPI spec."""
        try:
            data = self._ensure_dict(content)
        except Exception:
            return False
        version = data.get("openapi", "")
        return any(version.startswith(v) for v in self.SUPPORTED_VERSIONS)

    def parse(self, content: dict | str | bytes) -> APISpec:
        """Parse OpenAPI content into APISpec."""
        self._warnings = []  # reset
        data = self._ensure_dict(content)

        # Validate version
        version_str = data.get("openapi", "")
        if not any(version_str.startswith(v) for v in self.SUPPORTED_VERSIONS):
            raise UnsupportedSpecError(
                f"Unsupported OpenAPI version: {version_str!r}. "
                f"Supported: {self.SUPPORTED_VERSIONS}"
            )

        spec_format = (
            SpecFormat.OPENAPI_3_1
            if version_str.startswith("3.1")
            else SpecFormat.OPENAPI_3_0
        )

        # Validate required structure
        errors = self._validate_structure(data)
        if errors:
            if not self.lenient:
                raise SpecParseError("OpenAPI spec is malformed", errors=errors)
            for err in errors:
                self._add_warning("MALFORMED_STRUCTURE", err)

        # Parse info
        info = data.get("info", {})
        name = info.get("title", "Untitled API")
        version = info.get("version", "unknown")
        description = info.get("description")

        # Parse servers / base URL
        servers = data.get("servers", [])
        base_url = servers[0]["url"] if servers else ""
        server_urls = [s.get("url", "") for s in servers if s.get("url")]

        # Parse security schemes (auth)
        auth_schemes = self._parse_security_schemes(
            data.get("components", {}).get("securitySchemes", {})
        )

        # Parse endpoints
        endpoints = self._parse_paths(
            data.get("paths", {}), components=data.get("components", {})
        )

        return APISpec(
            name=name,
            version=version,
            description=description,
            source_format=spec_format,
            base_url=base_url,
            servers=server_urls,
            auth_schemes=auth_schemes,
            endpoints=endpoints,
            warnings=list(self._warnings),
            metadata={
                "openapi_version": version_str,
                "spec_size_endpoints": len(endpoints),
            },
        )

    # ---------- Validation ----------

    def _validate_structure(self, data: dict) -> list[str]:
        """Check for required top-level fields. Returns list of error messages."""
        errors = []
        if "info" not in data:
            errors.append("Missing required field: 'info'")
        elif "title" not in data["info"] or "version" not in data["info"]:
            errors.append("'info' must contain 'title' and 'version'")
        if "paths" not in data:
            errors.append("Missing required field: 'paths'")
        return errors

    # ---------- $ref resolution ----------

    def _resolve_ref(self, ref: str, components: dict) -> dict:
        """Resolve an internal $ref like '#/components/schemas/Pet'."""
        if not ref.startswith("#/"):
            # External ref — security: do not fetch
            self._add_warning(
                "EXTERNAL_REF_SKIPPED",
                f"External $ref not resolved (security policy): {ref}",
            )
            return {}

        parts = ref.lstrip("#/").split("/")
        current: Any = {"components": components}
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                self._add_warning(
                    "UNRESOLVED_REF",
                    f"Could not resolve $ref: {ref}",
                )
                if not self.lenient:
                    raise UnresolvedRefError(f"Cannot resolve $ref: {ref}")
                return {}
            current = current[part]
        return current if isinstance(current, dict) else {}

    def _resolve_if_ref(self, obj: dict, components: dict) -> dict:
        """If obj has a $ref, resolve it; otherwise return obj unchanged."""
        if isinstance(obj, dict) and "$ref" in obj:
            return self._resolve_ref(obj["$ref"], components)
        return obj

    # ---------- Schema parsing ----------

    def _parse_schema(self, schema_dict: dict, components: dict) -> SchemaSpec:
        """Convert an OpenAPI schema dict into our SchemaSpec model."""
        if not isinstance(schema_dict, dict):
            return SchemaSpec()
        schema_dict = self._resolve_if_ref(schema_dict, components)

        properties = {}
        for prop_name, prop_schema in schema_dict.get("properties", {}).items():
            properties[prop_name] = self._parse_schema(prop_schema, components)

        items = None
        if "items" in schema_dict:
            items = self._parse_schema(schema_dict["items"], components)

        return SchemaSpec(
            type=schema_dict.get("type"),
            format=schema_dict.get("format"),
            enum=schema_dict.get("enum"),
            properties=properties,
            required=schema_dict.get("required", []),
            items=items,
            example=schema_dict.get("example"),
            description=schema_dict.get("description"),
            nullable=schema_dict.get("nullable", False),
            raw=schema_dict,
        )

    # ---------- Security schemes (auth) ----------

    def _parse_security_schemes(self, schemes: dict) -> dict[str, AuthSpec]:
        result = {}
        for name, scheme in schemes.items():
            scheme_type = scheme.get("type", "").lower()

            if scheme_type == "apikey":
                auth_type = AuthType.API_KEY
            elif scheme_type == "http":
                scheme_name = scheme.get("scheme", "").lower()
                if scheme_name == "bearer":
                    auth_type = AuthType.BEARER
                elif scheme_name == "basic":
                    auth_type = AuthType.BASIC
                else:
                    auth_type = AuthType.UNKNOWN
            elif scheme_type == "oauth2":
                auth_type = AuthType.OAUTH2
            else:
                auth_type = AuthType.UNKNOWN

            result[name] = AuthSpec(
                type=auth_type,
                location=scheme.get("in"),
                name=scheme.get("name"),
                scheme=scheme.get("scheme"),
                bearer_format=scheme.get("bearerFormat"),
                flows=scheme.get("flows", {}),
                description=scheme.get("description"),
            )
        return result

    # ---------- Paths / Endpoints ----------

    def _parse_paths(self, paths: dict, components: dict) -> list[Endpoint]:
        endpoints = []
        valid_methods = {m.value.lower(): m for m in HTTPMethod}

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters apply to all operations on this path
            path_level_params = path_item.get("parameters", [])

            for method_key, op in path_item.items():
                if method_key.lower() not in valid_methods:
                    continue
                if not isinstance(op, dict):
                    continue

                endpoints.append(
                    self._parse_operation(
                        path=path,
                        method=valid_methods[method_key.lower()],
                        operation=op,
                        path_level_params=path_level_params,
                        components=components,
                    )
                )
        return endpoints

    def _parse_operation(
        self,
        *,
        path: str,
        method: HTTPMethod,
        operation: dict,
        path_level_params: list,
        components: dict,
    ) -> Endpoint:
        # Validate responses presence (in strict mode this is an error)
        if "responses" not in operation:
            self._add_warning(
                "MISSING_RESPONSES",
                f"Operation {method.value} {path} has no 'responses' field",
                location=f"paths.{path}.{method.value.lower()}",
            )

        # Parameters: merge path-level + operation-level
        params = self._parse_parameters(
            path_level_params + operation.get("parameters", []),
            components,
        )

        # Request body
        request_body = None
        if "requestBody" in operation:
            request_body = self._parse_request_body(
                operation["requestBody"], components
            )

        # Responses
        responses = {}
        for status_code, resp in operation.get("responses", {}).items():
            responses[status_code] = self._parse_response(
                status_code, resp, components
            )

        # Security
        security = self._parse_security_requirements(
            operation.get("security", [])
        )

        return Endpoint(
            path=path,
            method=method,
            operation_id=operation.get("operationId"),
            summary=operation.get("summary"),
            description=operation.get("description"),
            tags=operation.get("tags", []),
            parameters=params,
            request_body=request_body,
            responses=responses,
            security=security,
            deprecated=operation.get("deprecated", False),
            source_metadata={"path": path, "method": method.value},
        )

    def _parse_parameters(self, params: list, components: dict) -> list[Parameter]:
        result = []
        location_map = {loc.value: loc for loc in ParameterLocation}

        for p in params:
            p = self._resolve_if_ref(p, components)
            if not p:
                continue

            loc_str = p.get("in", "")
            if loc_str not in location_map:
                self._add_warning(
                    "INVALID_PARAM_LOCATION",
                    f"Parameter '{p.get('name', 'unknown')}' has invalid 'in': {loc_str}",
                )
                continue

            result.append(
                Parameter(
                    name=p.get("name", ""),
                    location=location_map[loc_str],
                    required=p.get("required", False),
                    schema=self._parse_schema(p.get("schema", {}), components),
                    example=p.get("example"),
                    description=p.get("description"),
                )
            )
        return result

    def _parse_request_body(self, body: dict, components: dict) -> RequestBody:
        body = self._resolve_if_ref(body, components)
        required = body.get("required", False)
        content = body.get("content", {})
        # Prefer JSON, fall back to whatever's there
        content_type = "application/json"
        if "application/json" not in content and content:
            content_type = next(iter(content.keys()))
        media = content.get(content_type, {})
        return RequestBody(
            required=required,
            content_type=content_type,
            schema=self._parse_schema(media.get("schema", {}), components),
            example=media.get("example"),
        )

    def _parse_response(
        self, status_code: str, resp: dict, components: dict
    ) -> Response:
        resp = self._resolve_if_ref(resp, components)
        description = resp.get("description", "")
        content = resp.get("content", {})
        content_type = None
        schema = None
        if content:
            content_type = (
                "application/json"
                if "application/json" in content
                else next(iter(content.keys()))
            )
            schema = self._parse_schema(
                content[content_type].get("schema", {}), components
            )
        return Response(
            status_code=status_code,
            description=description,
            content_type=content_type,
            schema=schema,
        )

    def _parse_security_requirements(
        self, sec_list: list
    ) -> list[SecurityRequirement]:
        result = []
        for req in sec_list:
            if not isinstance(req, dict):
                continue
            for scheme_name, scopes in req.items():
                result.append(
                    SecurityRequirement(
                        scheme_name=scheme_name,
                        scopes=scopes if isinstance(scopes, list) else [],
                    )
                )
        return result
