from __future__ import annotations

from django.db import transaction
from django.contrib.auth import get_user_model
from tools.models import NormalizedCapability, SchemaSource, RiskLevel, AccessGrant
from tools.utils.norm_cache import get_cached_normalization, set_cached_normalization
from tools.utils.mcp_notify import notify_capabilities_changed
from tools.utils.helpers import get_create_by_info_from_request
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
import copy
try:
    import yaml  # noqa: F401
    HAS_YAML = True
except Exception:
    HAS_YAML = False


VERBS = {"get","list","create","update","delete","patch","put","post","remove","set"}
OAS_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

_path_segment_re = re.compile(r"[{}]+")


def _parse_bool(value: Any) -> Optional[bool]:
    """
    Interpret common string representations of booleans.
    Returns None if value cannot be parsed.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        val = value.strip().lower()
        if val in {"true", "1", "yes", "on"}:
            return True
        if val in {"false", "0", "no", "off"}:
            return False
    return None


def _first_non_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _clean_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _index_tags(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Build a lookup of tag name -> tag metadata to enrich capabilities with tag context.
    """
    tags = {}
    for tag in doc.get("tags", []) or []:
        if isinstance(tag, dict):
            name = tag.get("name")
            if isinstance(name, str) and name:
                tags[name] = tag
    return tags


def _extract_examples(media_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract inline examples from a media object (request/response content entry).
    Returns a mapping of example_name -> example_payload.
    """
    if not isinstance(media_obj, dict):
        return {}

    examples: Dict[str, Any] = {}

    if "example" in media_obj:
        examples["default"] = copy.deepcopy(media_obj["example"])

    raw_examples = media_obj.get("examples")
    if isinstance(raw_examples, dict):
        for key, example in raw_examples.items():
            if isinstance(example, dict):
                if "value" in example:
                    examples[key] = copy.deepcopy(example["value"])
                elif "externalValue" in example:
                    examples[key] = {"externalValue": example["externalValue"]}

    schema = media_obj.get("schema")
    if isinstance(schema, dict):
        schema_example = schema.get("example")
        if schema_example is not None and "default" not in examples:
            examples["schema_default"] = copy.deepcopy(schema_example)
        schema_examples = schema.get("examples")
        if isinstance(schema_examples, (list, tuple)):
            for idx, item in enumerate(schema_examples):
                examples[f"schema_example_{idx}"] = copy.deepcopy(item)

    return examples


def _find_success_response(op: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Locate the primary success response object for an operation.
    Preference: 201, 200, then any 2xx response.
    """
    responses = op.get("responses", {})
    if not isinstance(responses, dict):
        return None, None

    for code in ("201", "200"):
        resp = responses.get(code)
        if isinstance(resp, dict):
            return code, resp

    for code, resp in responses.items():
        if str(code).startswith("2") and isinstance(resp, dict):
            return str(code), resp
    return None, None


def _build_request_details(op: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect descriptive request information beyond the JSON schema.
    """
    body = op.get("requestBody")
    if not isinstance(body, dict):
        return {}

    details: Dict[str, Any] = {}
    desc = _clean_text(body.get("description"))
    if desc:
        details["description"] = desc

    required = _parse_bool(body.get("required"))
    if required is not None:
        details["required"] = required

    content = body.get("content")
    if isinstance(content, dict):
        media_types: List[str] = []
        examples: Dict[str, Any] = {}
        for mt, media in content.items():
            if not isinstance(mt, str) or not isinstance(media, dict):
                continue
            media_types.append(mt)
            extracted = _extract_examples(media)
            if extracted:
                examples[mt] = extracted
        if media_types:
            details["media_types"] = sorted(set(media_types))
        if examples:
            details["examples"] = examples
    return details


def _build_response_details(op: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect descriptive response information to guide AI agents.
    """
    code, resp = _find_success_response(op)
    if not resp:
        return {}

    details: Dict[str, Any] = {"status_code": code} if code else {}
    desc = _clean_text(resp.get("description"))
    if desc:
        details["description"] = desc

    content = resp.get("content")
    if isinstance(content, dict):
        media_types: List[str] = []
        examples: Dict[str, Any] = {}
        for mt, media in content.items():
            if not isinstance(mt, str) or not isinstance(media, dict):
                continue
            media_types.append(mt)
            extracted = _extract_examples(media)
            if extracted:
                examples[mt] = extracted
        if media_types:
            details["media_types"] = sorted(set(media_types))
        if examples:
            details["examples"] = examples
    return details


def _extract_security(op: Dict[str, Any], doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    security = op.get("security", ...)
    if security is ...:
        security = doc.get("security", [])
    if isinstance(security, list):
        cleaned = [copy.deepcopy(item) for item in security if isinstance(item, dict)]
        return cleaned
    return []


def _collect_scopes(op: Dict[str, Any], tag_index: Dict[str, Dict[str, Any]], doc: Dict[str, Any]) -> List[str]:
    scopes: List[str] = []
    seen = set()

    def _add(values):
        if isinstance(values, (list, tuple, set)):
            for value in values:
                if isinstance(value, str) and value not in seen:
                    seen.add(value)
                    scopes.append(value)

    _add(op.get("x-scopes"))
    for tag_name in op.get("tags", []) or []:
        tag_meta = tag_index.get(tag_name) or {}
        _add(tag_meta.get("x-scopes"))
    _add(doc.get("x-scopes"))
    return scopes

def _load_doc(raw: bytes) -> Dict[str, Any]:
    """
    Try JSON first; fall back to YAML if available.
    """
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        if not HAS_YAML:
            raise ValueError("Spec is not valid JSON and PyYAML is not installed.")
        try:
            return yaml.safe_load(raw)
        except Exception as e:
            raise ValueError(f"Unable to parse spec as JSON or YAML: {e}") from e


def validate_openapi_v3(doc: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Tiny validator for OpenAPI 3.x:
      - has 'openapi' starting with '3.'
      - has 'paths' object with at least one path
    Returns: (version_str, doc)
    """
    if not isinstance(doc, dict):
        raise ValueError("OpenAPI document must be an object")
    ver = doc.get("openapi", "")
    if not isinstance(ver, str) or not ver.startswith("3."):
        raise ValueError("Only OpenAPI 3.x documents are supported in v1")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("OpenAPI 'paths' must be a non-empty object")
    return ver, doc



def _derive_resource_action(path: str, method: str, op: Dict[str, Any]) -> Tuple[str, str]:
    """
    Prefer operationId, mapping to resource.action.
    - If operationId looks like CreateAccount → account.create
    - Else fallback to path-derived resource and HTTP method as action.
    """
    op_id = op.get("operationId")
    if isinstance(op_id, str) and op_id.strip():
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", op_id).lower()  # camelCase/PascalCase → snake
        parts = re.split(r"[.\-_:/\s]+", snake)

        # Try to find a leading verb and last noun-ish token
        if parts:
            first = parts[0]
            last = parts[-1]
            if first in VERBS and len(parts) >= 2:
                # e.g., create + account, create + user, list + accounts
                resource = last
                action = first
                return resource, action

            # If last is a verb (e.g., account_create), flip
            if last in VERBS and len(parts) >= 2:
                resource = parts[0]
                action = last
                return resource, action

            # Fallback: 2+ segments → resource=first noun, action=last token
            if len(parts) >= 2:
                return parts[0], parts[-1]

            # Single segment → use method as action
            return parts[0], method

    # fallback from path
    segs = [s for s in path.split("/") if s and not s.startswith("{")]
    resource = segs[0] if segs else "root"
    return resource, method


def _build_input_schema(path: str, method: str, op: Dict[str, Any]) -> Dict[str, Any]:
    props = {}
    required = set()

    for p in op.get("parameters", []):
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not name:
            continue
        loc = p.get("in", "query")
        schema = p.get("schema") or {"type": "string"}
        prop_schema = copy.deepcopy(schema)
        desc = _clean_text(p.get("description"))
        if desc:
            prop_schema.setdefault("description", desc)
        example = p.get("example")
        if example is not None:
            prop_schema["example"] = copy.deepcopy(example)
        examples = p.get("examples")
        if isinstance(examples, dict):
            extracted_examples = {}
            for key, value in examples.items():
                if isinstance(value, dict):
                    if "value" in value:
                        extracted_examples[key] = copy.deepcopy(value["value"])
                    elif "externalValue" in value:
                        extracted_examples[key] = {"externalValue": value["externalValue"]}
            if extracted_examples:
                prop_schema["examples"] = extracted_examples
        deprecated = _parse_bool(p.get("deprecated"))
        if deprecated is not None:
            prop_schema["deprecated"] = deprecated
        props[name] = prop_schema
        if _parse_bool(p.get("required")):
            required.add(name)
        if isinstance(props[name], dict):
            props[name].setdefault("x-param-in", loc)

    # Path params from template
    for m in re.finditer(r"{([^}]+)}", path or ""):
        pname = m.group(1)
        props.setdefault(pname, {"type": "string", "x-param-in": "path"})
        required.add(pname)

    # requestBody (JSON only for v1)
    body = op.get("requestBody", {})
    content = body.get("content") if isinstance(body, dict) else {}
    app_json = content.get("application/json") if isinstance(content, dict) else None
    if isinstance(app_json, dict):
        body_schema = app_json.get("schema")
        if isinstance(body_schema, dict):
            body_prop = copy.deepcopy(body_schema)

            desc = _clean_text(body.get("description") or app_json.get("description"))
            examples = _extract_examples(app_json)

            if desc:
                if "$ref" in body_prop and len(body_prop) == 1:
                    body_prop = {"allOf": [body_prop], "description": desc}
                else:
                    body_prop.setdefault("description", desc)
            if examples:
                if "$ref" in body_prop and len(body_prop) == 1:
                    wrapper = {"allOf": [body_prop]}
                    wrapper["x-examples"] = examples
                    body_prop = wrapper
                else:
                    body_prop.setdefault("x-examples", examples)

            props["body"] = body_prop
            if _parse_bool(body.get("required")):
                required.add("body")

    schema = {
        "type": "object",
        "properties": props,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = sorted(required)
    return schema



def _select_success_response_schema(op: Dict[str, Any]) -> Dict[str, Any] | None:
    def first_json_schema(resp_obj: Dict[str, Any]) -> Dict[str, Any] | None:
        content = resp_obj.get("content", {})
        if not isinstance(content, dict):
            return None
        # Prefer application/json*, but accept any json-ish content type
        for mt, c in content.items():
            if not isinstance(mt, str) or "json" not in mt:
                continue
            if isinstance(c, dict):
                schema = c.get("schema")
                if isinstance(schema, dict):
                    return copy.deepcopy(schema)
        return None

    code, resp_obj = _find_success_response(op)
    if not resp_obj:
        return None
    found = first_json_schema(resp_obj)
    if found is not None:
        return found
    return None


def _build_wire(provider, doc: Dict[str, Any], path: str, method: str, op: Dict[str, Any], tag_index: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build minimal 'wire' hints for the gateway:
    - method: HTTP verb
    - path: path template (as in OAS)
    - path_map: { paramName: "paramName" } for all {params} in path
    - query_map: { paramName: "paramName" } for query params
    - headers: {} (reserved; fill in later if needed)
    """
    # Path params present in template
    path_params = {m.group(1) for m in re.finditer(r"{([^}]+)}", path or "")}
    path_map = {p: p for p in path_params}

    query_map = {}
    header_map = {}
    for p in op.get("parameters", []):
        if isinstance(p, dict) and p.get("in") == "query":
            name = p.get("name")
            if name:
                query_map[name] = name
        if isinstance(p, dict) and p.get("in") == "header":
            name = p.get("name")
            if name:
                header_map[name] = name

    wire: Dict[str, Any] = {
        "method": method.upper(),
        "path": path,
        "path_map": path_map,
        "query_map": query_map,
        "headers": header_map,
    }

    operation_id = _clean_text(op.get("operationId"))
    if operation_id:
        wire["operation_id"] = operation_id

    summary = _clean_text(op.get("summary"))
    if summary:
        wire["summary"] = summary

    description = _clean_text(op.get("description"))
    if description:
        wire["description"] = description

    tag_details: List[Dict[str, Any]] = []
    for tag_name in op.get("tags", []) or []:
        if not isinstance(tag_name, str):
            continue
        detail: Dict[str, Any] = {"name": tag_name}
        tag_meta = tag_index.get(tag_name) or {}
        tag_desc = _clean_text(tag_meta.get("description"))
        if tag_desc:
            detail["description"] = tag_desc
        scopes = tag_meta.get("x-scopes")
        if isinstance(scopes, (list, tuple)):
            detail["scopes"] = [s for s in scopes if isinstance(s, str)]
        tag_details.append(detail)
    if tag_details:
        wire["tags"] = tag_details

    scopes = _collect_scopes(op, tag_index, doc)
    if scopes:
        wire["scopes"] = sorted(scopes)

    tenant = _first_non_none(op.get("x-tenant"), doc.get("x-tenant"))
    if tenant:
        wire["tenant"] = tenant

    team = _first_non_none(op.get("x-team"), doc.get("x-team"))
    if team:
        wire["team"] = team

    visibility = _first_non_none(op.get("x-visibility"), doc.get("x-visibility"))
    if visibility:
        wire["visibility"] = visibility

    enabled = _first_non_none(_parse_bool(op.get("x-enabled")), _parse_bool(doc.get("x-enabled")))
    if enabled is not None:
        wire["enabled"] = enabled

    hot_reload = _first_non_none(_parse_bool(op.get("x-hot-reload")), _parse_bool(doc.get("x-hot-reload")))
    if hot_reload is not None:
        wire["hot_reload"] = hot_reload

    security = _extract_security(op, doc)
    if security:
        wire["security"] = security

    request_details = _build_request_details(op)
    if request_details:
        wire["request"] = request_details

    response_details = _build_response_details(op)
    if response_details:
        wire["response"] = response_details

    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    title = _clean_text(info.get("title"))
    version = _clean_text(info.get("version"))
    if title or version:
        wire["document"] = {}
        if title:
            wire["document"]["title"] = title
        if version:
            wire["document"]["version"] = version

    doc_desc = _clean_text(info.get("description"))
    if doc_desc:
        wire.setdefault("document", {})
        wire["document"]["description"] = doc_desc

    servers = doc.get("servers")
    if isinstance(servers, list) and servers:
        wire["servers"] = copy.deepcopy(servers)

    if provider:
        provider_payload = {
            "id": str(getattr(provider, "id", "")),
            "slug": getattr(provider, "slug", None),
            "name": getattr(provider, "name", None),
            "base_url": getattr(provider, "base_url", None),
        }
        wire["provider"] = {k: v for k, v in provider_payload.items() if v not in (None, "", [])}

    # Provide lightweight AI hints summarizing purpose and required inputs.
    required = None
    if isinstance(op.get("requestBody"), dict):
        required = _parse_bool(op["requestBody"].get("required"))
    schema_required = []
    # We cannot easily inspect json schema here, but we can hint at high-level requirement names.
    input_required = []
    for param in op.get("parameters", []) or []:
        if not isinstance(param, dict):
            continue
        is_required = _parse_bool(param.get("required"))
        if is_required and isinstance(param.get("name"), str):
            input_required.append(param["name"])
    if required:
        schema_required.append("body")
    if input_required or schema_required:
        wire["input_hints"] = {"required": sorted(set(input_required + schema_required))}

    return wire


def iter_operations(doc: Dict[str, Any]) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """
    Yield (path, method, operation_obj) for each operation in paths.
    """
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            m = method.lower()
            if m in OAS_HTTP_METHODS and isinstance(op, dict):
                yield path, m, op


def normalize_openapi(provider, doc_bytes: bytes) -> Tuple[str, Iterable[Dict[str, Any]]]:
    """
    Parse, minimally validate, and produce a stream of capability dicts:
      { "name": "resource.action",
        "json_schema_in": {..},
        "json_schema_out": {.. or None} }
    Returns (openapi_version, capabilities_iterable)
    """
    doc = _load_doc(doc_bytes)
    ver, _ = validate_openapi_v3(doc)

    tags = _index_tags(doc)
    caps = []
    for path, method, op in iter_operations(doc):
        resource, action = _derive_resource_action(path, method, op)
        input_schema = _build_input_schema(path, method, op)
        op_summary = _clean_text(op.get("summary"))
        if op_summary and "description" not in input_schema:
            input_schema["description"] = op_summary
        op_description = _clean_text(op.get("description"))
        if op_description:
            input_schema.setdefault("x-operation-description", op_description)

        out_schema = _select_success_response_schema(op)
        wire = _build_wire(provider, doc, path, method, op, tags)
        caps.append({
            "name": f"{provider.slug}.{resource}.{action}",
            "json_schema_in": input_schema,
            "json_schema_out": out_schema,
            "wire": wire,
        })
    return ver, caps


def normalize_and_persist(request, src: SchemaSource) -> dict:
    """
    Normalizes the uploaded schema source into NormalizedCapability rows.
    Uses Redis cache keyed by (kind, sha256) to avoid re-parsing unchanged specs.
    Always creates a new provider version (v = max + 1), then notifies MCP.
    Returns a NormalizeResultSerializer-compatible dict.
    """
    print(f"Normalizing and persisting SchemaSource id={src.id} tenant={src.tenant.slug} provider={src.provider.name}")
    # Load raw bytes
    with src.blob.open("rb") as f:
        raw = f.read()

    # Cache hit?
    cached = get_cached_normalization(src.kind, src.sha256) if src.sha256 else None
    if cached:
        oas_ver = cached.get("openapi_version", "")
        caps = cached.get("caps", [])
    else:
        # Parse and normalize
        try:
            oas_ver, caps = normalize_openapi(src.provider, raw)
        except ValueError as e:
            raise ValueError(f"Validation error: {e}") from e
        # cache the result
        if src.sha256:
            set_cached_normalization(src.kind, src.sha256, {"openapi_version": oas_ver, "caps": caps})

    print(f"Normalized {[cap.get('name', 'NA') for cap in caps]} capabilities from SchemaSource id={src.id}")
    # Next version
    qs = NormalizedCapability.objects.filter(provider=src.provider)
    next_version = (qs.order_by("-version").values_list("version", flat=True).first() or 0) + 1

    created = 0
    created_by, created_by_type, created_by_identifier = get_create_by_info_from_request(request)
    with transaction.atomic():
        bulk = []
        for cap in caps:
            bulk.append(NormalizedCapability(
                tenant=request.user.tenant,
                created_by=created_by,
                created_by_type=created_by_type,
                created_by_identifier=created_by_identifier,
                provider=src.provider,
                version=next_version,
                name=cap["name"],
                json_schema_in=cap["json_schema_in"],
                json_schema_out=cap.get("json_schema_out"),
                risk_level=RiskLevel.LOW,
                enabled=True,
                wire=cap.get("wire") or {},
            ))
        if bulk:
            NormalizedCapability.objects.bulk_create(bulk)

            # seed access grants since bulk_create doesn't trigger signals
            AccessGrant.objects.bulk_create([
                AccessGrant(
                    team=request.user.default_team,
                    capability=cap,
                    version=next_version,
                    scopes=NormalizedCapability.DEFAULT_SCOPES,
                    approved_by=request.user if not getattr(request.user, 'is_service_principal', False) else None,
                    approved_by_type=request.user.__class__.__name__,
                    approved_by_identifier=(
                        request.user.identifier if hasattr(request.user, 'identifier')  # ServicePrincipal
                        else request.user.email),                                       # User
                ) for cap in bulk
            ])
            created = len(bulk)

    # Best-effort notify MCPs to hot-reload (after rows are committed)
    print(f"Notifying MCP of capability changes for tenant={src.tenant.slug} provider={src.provider.name}")
    try:
        owner_team_id = src.provider.owner_team_id
        notify_capabilities_changed(tenant_slug=src.tenant.slug, team_ids=[owner_team_id])
    except Exception as e:
        print(f"Warning: unable to notify MCP of capability changes: {e}")

    return {
        "provider_id": str(src.provider_id),
        "version": next_version,
        "count_created": created,
        "openapi_version": oas_ver,
        "sample": list(caps[:5]),
    }
