# API Analysis Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the 4 tools explicitly deferred by the web-tools-migration plan for needing "a design decision (e.g. use the `requests` library instead of shelling out) before porting": `jwt_analyzer_scan`, `api_fuzzer_scan`, `api_schema_analyzer_scan`, `graphql_scanner_scan`. Extends `web` from 26 to 30 tools.

**The design decision, resolved:** unlike every other tool ported so far, these four don't wrap a single external CLI binary and return `run_tool_command`'s `{success, command, output, error, execution_time, cached}` shape. Legacy builds a **custom analysis result dict** per tool (`jwt_analysis_results`, `graphql_scan_results`, `schema_analysis_results`, or a `fuzzing_type`/`results` pair) by making one or more HTTP calls (legacy shells out to `curl`) and inspecting the response body. Inspection of `hexstrike/core/registry.py` (`ToolSpec.handler: Callable`, no return-shape constraint), `hexstrike/api/app.py` (`create_tool_view` does `jsonify(spec.handler(**payload))` — passes the return value straight through) and `hexstrike/mcp/server.py` (never touches the handler's return shape) confirms nothing downstream requires the `run_tool_command` shape. This plan therefore has each handler call Python's `requests` library directly (already a project dependency — used in `hexstrike/mcp/client.py`) instead of shelling out to `curl`, and returns the same custom, tool-specific result shape legacy did. `api_fuzzer_scan`'s "endpoint discovery" mode (no `endpoints` given) is unaffected — it still runs `ffuf` as a normal subprocess via `run_tool_command`, same as every other CLI-wrapper tool; only its "specific endpoints" mode (looping HTTP requests) switches to `requests`.

**Architecture:** New functions appended to `hexstrike/tools/web.py` (no new category — these are web-security analysis tools). `import requests`, `import base64`, `import json` added to `web.py`'s imports (the latter two were legacy's local imports inside the function bodies; module-level is idiomatic and has no behavioral difference since they're pure stdlib with no import-time side effects).

**Tech Stack:** Python 3.13, pytest, `requests` (already a dependency) — no new dependencies added.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`. Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`. Confirmed legacy's real `execute_command`/`EnhancedCommandExecutor` (distinct from this project's simpler `ProcessManager`) returns a dict with a `"stdout"` key — so every `result.get("stdout", "")` check in the legacy analysis logic below is reading real captured output, not a dead/always-empty lookup.

## Global Constraints

- **HTTP calls get an explicit finite timeout** (`timeout=30` seconds for POST/GET probes, `timeout=10` for `api_fuzzer_scan`'s per-endpoint requests) — a deliberate addition, not present as an explicit value in legacy. Legacy's `curl` calls ran through the same generic subprocess executor as every other tool, which imposes some timeout at that layer; `requests` calls with no `timeout=` argument can hang indefinitely, which the old subprocess-timeout safety net no longer provides once `requests` replaces `curl`. This is a deliberate safety addition, called out here rather than silently introduced.
- **Network failures are caught, not propagated**: every `requests.get`/`requests.post`/`requests.request` call is wrapped in `try/except requests.RequestException`, treating a failed HTTP call as "empty response body" for the string-matching checks below (or an explicit failure entry for `api_fuzzer_scan`'s per-request results) rather than letting the exception bubble into a 500. Legacy's subprocess-based `execute_command` never raised on a failed `curl` invocation either (it returned `{"success": False, ...}` and the analysis code just read an empty/missing `"stdout"`), so this preserves the same "a failed probe looks like an empty response" behavior.
- **Preserve string-matching checks on response BODY TEXT verbatim, not real status codes** — this is intentional, not a bug to fix: legacy's `jwt_analyzer`/`graphql_scanner` check whether the substring `"200"` or `"data"` or `"error"` appears anywhere in the raw response text (`result.get("stdout", "")`), never the actual HTTP status code. `requests.Response.text` is the direct equivalent of legacy's captured `stdout`. Do not "upgrade" these to `response.status_code == 200` checks — that would be a behavior change, not a faithful port.
- **`graphql_scanner_scan`'s introspection query string is copied verbatim, including its indentation** — the legacy triple-quoted string's exact interior whitespace (leading spaces on each line, from being nested 3 indent-levels deep in the original Flask route) feeds directly into `.replace('\n', ' ').replace('  ', ' ')`, producing a specific (slightly irregular — a single `.replace('  ', ' ')` pass does not fully collapse a run of 9 spaces down to 1) `clean_query` string. Reproduce the exact legacy literal, character for character, not a re-indented "cleaner" version — see Task 3 for the literal text to copy.
- **`test_mutations`/`mutations` stays a declared, unused parameter on `graphql_scanner_scan`** — legacy reads `params.get("test_mutations", True)` into a local variable that is never referenced again anywhere in the function. This looks like dead legacy code, not a hook this plan should wire up; per the "parameter names are part of the public API/MCP schema" constraint applied throughout this project, the parameter is kept (as `test_mutations: bool = True`) for interface parity even though it does nothing, exactly as it did nothing in legacy.
- **`api_schema_analyzer_scan`'s fetch-failure path returns `{"success": False, "error": ...}` with an implicit 200**, not a manual 400 — legacy returned `jsonify({"error": ...}), 400` here, but this project's `create_tool_view` (`hexstrike/api/app.py`) only sets a non-200 status on a `TypeError`/`Exception` escaping the handler, never by inspecting the handler's own returned dict. This is the exact same behavior every other tool's `run_tool_command`-based soft-failure path already has (e.g. `is_tool_available` returning `False`) — not a new kind of deviation, just this tool hitting the same established pattern.
- **`api_fuzzer_scan`'s per-request result shape is intentionally NOT curl's raw output shape** — legacy's `result` sub-dict under `{"endpoint", "method", "result"}` was whatever `execute_command`'s `EnhancedCommandExecutor` produced for a `curl -w '%{http_code}|%{size_download}'` invocation (a `stdout` string like `"200|1483"` plus process metadata). Since this plan replaces that curl call with `requests.request(...)`, the equivalent, more directly useful information — `response.status_code` and `len(response.content)` — is returned as `{"success": True, "status_code": ..., "size": ...}` (or `{"success": False, "error": str(exc)}` on failure) instead of trying to fabricate a fake curl-shaped stdout string. This preserves the *functional intent* (per-endpoint/method HTTP probe results) without pretending the transport mechanism didn't change.
- **`additional_args` is not applicable to any of these four tools** — none of them build a `List[str]` CLI command in their HTTP-probing paths (only `api_fuzzer_scan`'s `ffuf` fallback branch does, and it already has its own fixed flag set matching legacy exactly, no `additional_args` in legacy's `api_fuzzer` either).
- **Legacy manual validation is not reproduced**: `jwt_token` (jwt_analyzer), `endpoint` (graphql_scanner), `schema_url` (api_schema_analyzer), `base_url` (api_fuzzer) become required parameters with no default; a missing value raises `TypeError` → 400 via `hexstrike/api/app.py`.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: `jwt_analyzer_scan`

**Legacy (`d689933:hexstrike_server.py:15005-15104`):** decodes JWT header/payload (base64 + `json.loads`, with padding correction), flags `alg: none`, HMAC algorithms, and missing `exp`; if `target_url` given, builds a forged `alg: none` token and probes the URL with it via `curl`, flagging acceptance if `"200"` or `"success"` appears in the response body.

**Produces:** `jwt_analyzer_scan(jwt_token, target_url=None)` → `"jwt_analyzer_scan"` at `/api/tools/jwt_analyzer`, category `"web"`. Returns `{"success": True, "jwt_analysis_results": {...}}` (not `run_tool_command`'s shape).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_analysis_tools.py`:

```python
import base64
import json
import pytest
import requests
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools


def _make_jwt(header: dict, payload: dict) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64(header)}.{b64(payload)}.sig"


def test_jwt_analyzer_scan_flags_none_algorithm_and_missing_exp():
    tool = ToolRegistry.get("jwt_analyzer_scan")
    assert tool is not None
    assert tool.category == "web"
    assert tool.endpoint == "/api/tools/jwt_analyzer"

    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "user1"})
    res = tool.handler(jwt_token=token)
    assert res["success"] is True
    vuln_types = {v["type"] for v in res["jwt_analysis_results"]["vulnerabilities"]}
    assert "none_algorithm" in vuln_types
    assert "no_expiration" in vuln_types
    assert res["jwt_analysis_results"]["token_info"]["algorithm"] == "none"


def test_jwt_analyzer_scan_flags_hmac_and_has_expiration():
    tool = ToolRegistry.get("jwt_analyzer_scan")
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "exp": 9999999999})
    res = tool.handler(jwt_token=token)
    vulns = res["jwt_analysis_results"]["vulnerabilities"]
    assert any(v["type"] == "hmac_algorithm" for v in vulns)
    assert not any(v["type"] == "no_expiration" for v in vulns)
    assert "hmac_key_confusion" in res["jwt_analysis_results"]["attack_vectors"]


def test_jwt_analyzer_scan_malformed_token():
    tool = ToolRegistry.get("jwt_analyzer_scan")
    res = tool.handler(jwt_token="not-a-real-jwt")
    vulns = res["jwt_analysis_results"]["vulnerabilities"]
    assert any(v["type"] in ("malformed_token", "invalid_format") for v in vulns)


def test_jwt_analyzer_scan_target_url_none_algorithm_accepted(monkeypatch):
    captured = {}

    class FakeResponse:
        text = "HTTP 200 success"

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(requests, "get", fake_get)

    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "exp": 9999999999})
    tool = ToolRegistry.get("jwt_analyzer_scan")
    res = tool.handler(jwt_token=token, target_url="http://api.example.com/protected")

    assert captured["url"] == "http://api.example.com/protected"
    assert captured["headers"]["Authorization"].startswith("Bearer ")
    forged = captured["headers"]["Authorization"].removeprefix("Bearer ")
    forged_header = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
    assert forged_header == {"alg": "none", "typ": "JWT"}
    assert any(v["type"] == "none_algorithm_accepted" for v in res["jwt_analysis_results"]["vulnerabilities"])


def test_jwt_analyzer_scan_target_url_request_failure_is_not_fatal(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(requests, "get", fake_get)

    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "exp": 9999999999})
    tool = ToolRegistry.get("jwt_analyzer_scan")
    res = tool.handler(jwt_token=token, target_url="http://unreachable.example.com")
    assert res["success"] is True
    assert not any(v["type"] == "none_algorithm_accepted" for v in res["jwt_analysis_results"]["vulnerabilities"])
```

- [ ] **Step 2: Run test to verify it fails** — `ToolRegistry.get("jwt_analyzer_scan")` returns `None`.

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/tools/web.py` (add `import base64`, `import json`, `import requests` near the top if not already present):

```python
@ToolRegistry.register(
    name="jwt_analyzer_scan",
    category="web",
    description="JWT token analysis and vulnerability testing",
    endpoint="/api/tools/jwt_analyzer"
)
def jwt_analyzer_scan(jwt_token: str, target_url: Optional[str] = None) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "token": jwt_token[:50] + "..." if len(jwt_token) > 50 else jwt_token,
        "vulnerabilities": [],
        "token_info": {},
        "attack_vectors": []
    }

    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            try:
                header = json.loads(base64.b64decode(header_b64))
                payload = json.loads(base64.b64decode(payload_b64))
                results["token_info"] = {
                    "header": header,
                    "payload": payload,
                    "algorithm": header.get("alg", "unknown")
                }
                algorithm = header.get("alg", "").lower()
                if algorithm == "none":
                    results["vulnerabilities"].append({
                        "type": "none_algorithm",
                        "severity": "CRITICAL",
                        "description": "JWT uses 'none' algorithm - no signature verification"
                    })
                if algorithm in ["hs256", "hs384", "hs512"]:
                    results["attack_vectors"].append("hmac_key_confusion")
                    results["vulnerabilities"].append({
                        "type": "hmac_algorithm",
                        "severity": "MEDIUM",
                        "description": "HMAC algorithm detected - vulnerable to key confusion attacks"
                    })
                exp = payload.get("exp")
                if not exp:
                    results["vulnerabilities"].append({
                        "type": "no_expiration",
                        "severity": "HIGH",
                        "description": "JWT token has no expiration time"
                    })
            except Exception as decode_error:
                results["vulnerabilities"].append({
                    "type": "malformed_token",
                    "severity": "HIGH",
                    "description": f"Token decoding failed: {str(decode_error)}"
                })
    except Exception:
        results["vulnerabilities"].append({
            "type": "invalid_format",
            "severity": "HIGH",
            "description": "Invalid JWT token format"
        })

    if target_url:
        none_token_parts = jwt_token.split('.')
        if len(none_token_parts) >= 2:
            none_header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
            none_token = f"{none_header}.{none_token_parts[1]}."
            try:
                response = requests.get(target_url, headers={"Authorization": f"Bearer {none_token}"}, timeout=30)
                body_text = response.text
            except requests.RequestException:
                body_text = ""
            if "200" in body_text or "success" in body_text.lower():
                results["vulnerabilities"].append({
                    "type": "none_algorithm_accepted",
                    "severity": "CRITICAL",
                    "description": "Server accepts tokens with 'none' algorithm"
                })

    return {"success": True, "jwt_analysis_results": results}
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit** (`feat(tools): port jwt_analyzer_scan to web tool registry via requests`)

---

### Task 2: `api_schema_analyzer_scan`

**Legacy (`d689933:hexstrike_server.py:15123-15211`):** fetches a schema URL via `curl`, parses JSON, and for `openapi`/`swagger` schemas walks `paths` flagging endpoints with no `security` and parameters whose name contains `password`/`token`/`key`/`secret`.

**Produces:** `api_schema_analyzer_scan(schema_url, schema_type="openapi")` → `"api_schema_analyzer_scan"` at `/api/tools/api_schema_analyzer`, category `"web"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_api_schema_analyzer_scan_flags_missing_auth_and_sensitive_param(monkeypatch):
    schema = {
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [{"name": "api_key", "in": "query"}],
                    "security": []
                }
            }
        }
    }

    class FakeResponse:
        ok = True
        text = json.dumps(schema)

    monkeypatch.setattr(requests, "get", lambda url, timeout=None: FakeResponse())

    tool = ToolRegistry.get("api_schema_analyzer_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/api_schema_analyzer"

    res = tool.handler(schema_url="http://api.example.com/openapi.json")
    assert res["success"] is True
    issues = res["schema_analysis_results"]["security_issues"]
    assert any(i["issue"] == "no_authentication" for i in issues)
    assert any(i["issue"] == "sensitive_parameter" for i in issues)
    assert len(res["schema_analysis_results"]["endpoints_found"]) == 1


def test_api_schema_analyzer_scan_fetch_failure(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda url, timeout=None: (_ for _ in ()).throw(requests.RequestException("timeout")))

    tool = ToolRegistry.get("api_schema_analyzer_scan")
    res = tool.handler(schema_url="http://unreachable.example.com/openapi.json")
    assert res["success"] is False
    assert res["error"] == "Failed to fetch API schema"


def test_api_schema_analyzer_scan_invalid_json(monkeypatch):
    class FakeResponse:
        ok = True
        text = "not json"

    monkeypatch.setattr(requests, "get", lambda url, timeout=None: FakeResponse())

    tool = ToolRegistry.get("api_schema_analyzer_scan")
    res = tool.handler(schema_url="http://api.example.com/openapi.json")
    assert res["success"] is True
    issues = res["schema_analysis_results"]["security_issues"]
    assert any(i["issue"] == "invalid_json" for i in issues)
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="api_schema_analyzer_scan",
    category="web",
    description="API schema analysis for security issues (OpenAPI/Swagger)",
    endpoint="/api/tools/api_schema_analyzer"
)
def api_schema_analyzer_scan(schema_url: str, schema_type: str = "openapi") -> Dict[str, Any]:
    try:
        response = requests.get(schema_url, timeout=30)
        schema_content = response.text
        fetch_ok = response.ok
    except requests.RequestException:
        schema_content = ""
        fetch_ok = False

    if not fetch_ok:
        return {"success": False, "error": "Failed to fetch API schema"}

    analysis_results: Dict[str, Any] = {
        "schema_url": schema_url,
        "schema_type": schema_type,
        "endpoints_found": [],
        "security_issues": [],
        "recommendations": []
    }

    try:
        schema_data = json.loads(schema_content)

        if schema_type.lower() in ["openapi", "swagger"]:
            paths = schema_data.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if isinstance(details, dict):
                        endpoint_info = {
                            "path": path,
                            "method": method.upper(),
                            "summary": details.get("summary", ""),
                            "parameters": details.get("parameters", []),
                            "security": details.get("security", [])
                        }
                        analysis_results["endpoints_found"].append(endpoint_info)

                        if not endpoint_info["security"]:
                            analysis_results["security_issues"].append({
                                "endpoint": f"{method.upper()} {path}",
                                "issue": "no_authentication",
                                "severity": "MEDIUM",
                                "description": "Endpoint has no authentication requirements"
                            })

                        for param in endpoint_info["parameters"]:
                            param_name = param.get("name", "").lower()
                            if any(sensitive in param_name for sensitive in ["password", "token", "key", "secret"]):
                                analysis_results["security_issues"].append({
                                    "endpoint": f"{method.upper()} {path}",
                                    "issue": "sensitive_parameter",
                                    "severity": "HIGH",
                                    "description": f"Sensitive parameter detected: {param_name}"
                                })

        if analysis_results["security_issues"]:
            analysis_results["recommendations"] = [
                "Implement authentication for all endpoints",
                "Use HTTPS for all API communications",
                "Validate and sanitize all input parameters",
                "Implement rate limiting",
                "Add proper error handling",
                "Use secure headers (CORS, CSP, etc.)"
            ]

    except json.JSONDecodeError:
        analysis_results["security_issues"].append({
            "endpoint": "schema",
            "issue": "invalid_json",
            "severity": "HIGH",
            "description": "Schema is not valid JSON"
        })

    return {"success": True, "schema_analysis_results": analysis_results}
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 3: `graphql_scanner_scan`

**Legacy (`d689933:hexstrike_server.py:14898-15005`):** three probes against a GraphQL endpoint — introspection query (flags if enabled), a deeply-nested query (flags if not rejected), and a batch of 10 queries (flags if accepted without rate limiting).

**Produces:** `graphql_scanner_scan(endpoint, introspection=True, query_depth=10, test_mutations=True)` → `"graphql_scanner_scan"` at `/api/tools/graphql_scanner`, category `"web"`.

**The introspection query literal — copy this exact text (same interior indentation) into the implementation, do not re-indent it:**

```
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            
```
(a leading newline before the first `{`, and a trailing newline + 12 spaces before the closing marker — this is exactly what Python's triple-quote literal captures from legacy's source at its original indentation depth.)

- [ ] **Step 1: Write the failing tests**

```python
def test_graphql_scanner_scan_flags_introspection_and_no_depth_limit_and_batch(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, text, ok=True):
            self.text = text
            self.ok = ok

    def fake_post(url, json=None, timeout=None):
        calls.append(json)
        if len(calls) == 1:
            return FakeResponse('{"data": {"__schema": {"types": []}}}')
        if len(calls) == 2:
            return FakeResponse('{"data": {"field": "ok"}}')
        return FakeResponse('{"data": [{"field": "ok"}]}', ok=True)

    monkeypatch.setattr(requests, "post", fake_post)

    tool = ToolRegistry.get("graphql_scanner_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/graphql_scanner"

    res = tool.handler(endpoint="http://api.example.com/graphql", query_depth=5)
    types = {v["type"] for v in res["graphql_scan_results"]["vulnerabilities"]}
    assert types == {"introspection_enabled", "no_query_depth_limit", "batch_queries_allowed"}
    assert res["graphql_scan_results"]["tests_performed"] == [
        "introspection_query", "query_depth_analysis", "batch_query_testing",
    ]
    assert len(res["graphql_scan_results"]["recommendations"]) == 5


def test_graphql_scanner_scan_no_vulnerabilities_when_protected(monkeypatch):
    class FakeResponse:
        def __init__(self, text, ok=True):
            self.text = text
            self.ok = ok

    def fake_post(url, json=None, timeout=None):
        return FakeResponse('{"errors": [{"message": "introspection disabled"}]}', ok=False)

    monkeypatch.setattr(requests, "post", fake_post)

    tool = ToolRegistry.get("graphql_scanner_scan")
    res = tool.handler(endpoint="http://api.example.com/graphql", introspection=False)
    assert res["graphql_scan_results"]["vulnerabilities"] == []
    assert res["graphql_scan_results"]["tests_performed"] == ["query_depth_analysis", "batch_query_testing"]


def test_graphql_scanner_scan_request_failure_is_not_fatal(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(requests, "post", fake_post)

    tool = ToolRegistry.get("graphql_scanner_scan")
    res = tool.handler(endpoint="http://unreachable.example.com/graphql")
    assert res["success"] is True
    assert res["graphql_scan_results"]["vulnerabilities"] == []
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="graphql_scanner_scan",
    category="web",
    description="GraphQL security scanning and introspection testing",
    endpoint="/api/tools/graphql_scanner"
)
def graphql_scanner_scan(endpoint: str, introspection: bool = True, query_depth: int = 10, test_mutations: bool = True) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "endpoint": endpoint,
        "tests_performed": [],
        "vulnerabilities": [],
        "recommendations": []
    }

    if introspection:
        introspection_query = '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            '''
        clean_query = introspection_query.replace('\n', ' ').replace('  ', ' ').strip()
        try:
            response = requests.post(endpoint, json={"query": clean_query}, timeout=30)
            body_text = response.text
        except requests.RequestException:
            body_text = ""

        results["tests_performed"].append("introspection_query")
        if "data" in body_text:
            results["vulnerabilities"].append({
                "type": "introspection_enabled",
                "severity": "MEDIUM",
                "description": "GraphQL introspection is enabled"
            })

    deep_query = "{ " * query_depth + "field" + " }" * query_depth
    try:
        response = requests.post(endpoint, json={"query": deep_query}, timeout=30)
        body_text = response.text
    except requests.RequestException:
        body_text = ""

    results["tests_performed"].append("query_depth_analysis")
    if "error" not in body_text.lower():
        results["vulnerabilities"].append({
            "type": "no_query_depth_limit",
            "severity": "HIGH",
            "description": f"No query depth limiting detected (tested depth: {query_depth})"
        })

    batch_query = [{"query": "{field}"} for _ in range(10)]
    try:
        response = requests.post(endpoint, json=batch_query, timeout=30)
        body_text = response.text
        batch_ok = response.ok
    except requests.RequestException:
        body_text = ""
        batch_ok = False

    results["tests_performed"].append("batch_query_testing")
    if "data" in body_text and batch_ok:
        results["vulnerabilities"].append({
            "type": "batch_queries_allowed",
            "severity": "MEDIUM",
            "description": "Batch queries are allowed without rate limiting"
        })

    if results["vulnerabilities"]:
        results["recommendations"] = [
            "Disable introspection in production",
            "Implement query depth limiting",
            "Add rate limiting for batch queries",
            "Implement query complexity analysis",
            "Add authentication for sensitive operations"
        ]

    return {"success": True, "graphql_scan_results": results}
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 4: `api_fuzzer_scan`

**Legacy (`d689933:hexstrike_server.py:14841-14894`):** if `endpoints` given, loops `endpoints × methods` making a `curl` request per combination; otherwise runs `ffuf` for wordlist-based discovery.

**Produces:** `api_fuzzer_scan(base_url, endpoints=None, methods=None, wordlist="/usr/share/wordlists/api/api-endpoints.txt")` → `"api_fuzzer_scan"` at `/api/tools/api_fuzzer`, category `"web"`. `methods` defaults to `["GET", "POST", "PUT", "DELETE"]` when not given (mutable-default-safe: computed inside the function body, matching legacy's `params.get("methods", ["GET", "POST", "PUT", "DELETE"])`).

- [ ] **Step 1: Write the failing tests**

```python
def test_api_fuzzer_scan_endpoint_testing_mode(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, status_code, content):
            self.status_code = status_code
            self.content = content

    def fake_request(method, url, timeout=None):
        calls.append((method, url))
        return FakeResponse(200, b"ok")

    monkeypatch.setattr(requests, "request", fake_request)

    tool = ToolRegistry.get("api_fuzzer_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/api_fuzzer"

    res = tool.handler(base_url="http://api.example.com/", endpoints=["/users"], methods=["GET", "POST"])
    assert res["success"] is True
    assert res["fuzzing_type"] == "endpoint_testing"
    assert calls == [("GET", "http://api.example.com/users"), ("POST", "http://api.example.com/users")]
    assert res["results"][0] == {"endpoint": "/users", "method": "GET", "result": {"success": True, "status_code": 200, "size": 2}}


def test_api_fuzzer_scan_endpoint_testing_mode_request_failure(monkeypatch):
    def fake_request(method, url, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(requests, "request", fake_request)

    tool = ToolRegistry.get("api_fuzzer_scan")
    res = tool.handler(base_url="http://api.example.com", endpoints=["/admin"], methods=["GET"])
    assert res["results"][0]["result"]["success"] is False
    assert "connection refused" in res["results"][0]["result"]["error"]


def test_api_fuzzer_scan_discovery_mode(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("api_fuzzer_scan")
    res = tool.handler(base_url="http://api.example.com")
    assert res["success"] is True
    assert res["fuzzing_type"] == "endpoint_discovery"
    assert captured["cmd"] == [
        "ffuf", "-u", "http://api.example.com/FUZZ", "-w", "/usr/share/wordlists/api/api-endpoints.txt",
        "-mc", "200,201,202,204,301,302,307,401,403,405", "-t", "50",
    ]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="api_fuzzer_scan",
    category="web",
    description="API endpoint fuzzing with intelligent parameter discovery",
    endpoint="/api/tools/api_fuzzer"
)
def api_fuzzer_scan(base_url: str, endpoints: Optional[List[str]] = None, methods: Optional[List[str]] = None, wordlist: str = "/usr/share/wordlists/api/api-endpoints.txt") -> Dict[str, Any]:
    if methods is None:
        methods = ["GET", "POST", "PUT", "DELETE"]

    if endpoints:
        results = []
        for endpoint in endpoints:
            for method in methods:
                test_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
                try:
                    response = requests.request(method, test_url, timeout=10)
                    result = {"success": True, "status_code": response.status_code, "size": len(response.content)}
                except requests.RequestException as exc:
                    result = {"success": False, "error": str(exc)}
                results.append({"endpoint": endpoint, "method": method, "result": result})
        return {"success": True, "fuzzing_type": "endpoint_testing", "results": results}

    cmd = ["ffuf", "-u", f"{base_url}/FUZZ", "-w", wordlist, "-mc", "200,201,202,204,301,302,307,401,403,405", "-t", "50"]
    result = run_tool_command(cmd)
    return {"success": True, "fuzzing_type": "endpoint_discovery", "result": result}
```

(Add `List` to the `typing` import in `hexstrike/tools/web.py` if not already present.)

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 5: Full verification

- [ ] **Step 1: Assert web category has exactly 30 tools** (update the existing `test_web_category_has_26_tools` in `tests/test_web_tools.py`).
- [ ] **Step 2: Run the entire test suite** — all PASS.
- [ ] **Step 3: MCP sanity check** — assert all 4 new tools present in `mcp.list_tools()`.
- [ ] **Step 4: Commit** (`test(tools): verify web category reaches 30-tool parity`)
