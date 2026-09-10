import base64
import json
import pytest
import requests
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
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
    res = tool.handler(jwt_token="abc.def.ghi")
    vulns = res["jwt_analysis_results"]["vulnerabilities"]
    assert any(v["type"] == "malformed_token" for v in vulns)


def test_jwt_analyzer_scan_single_segment_token_produces_no_vulnerabilities():
    tool = ToolRegistry.get("jwt_analyzer_scan")
    res = tool.handler(jwt_token="not-a-real-jwt")
    assert res["jwt_analysis_results"]["vulnerabilities"] == []


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
    def fake_get(url, timeout=None):
        raise requests.RequestException("timeout")

    monkeypatch.setattr(requests, "get", fake_get)

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
    # A failed request leaves body_text == "", and the depth-limit check is an
    # inverted "'error' not in body" test - an empty body reads as "no error
    # returned", which legacy (and this port) treats as vulnerable. This is a
    # faithfully-preserved legacy quirk, not something this test should "fix".
    def fake_post(url, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(requests, "post", fake_post)

    tool = ToolRegistry.get("graphql_scanner_scan")
    res = tool.handler(endpoint="http://unreachable.example.com/graphql")
    assert res["success"] is True
    types = {v["type"] for v in res["graphql_scan_results"]["vulnerabilities"]}
    assert types == {"no_query_depth_limit"}


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
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("api_fuzzer_scan")
    res = tool.handler(base_url="http://api.example.com")
    assert res["success"] is True
    assert res["fuzzing_type"] == "endpoint_discovery"
    assert captured["cmd"] == [
        "ffuf", "-u", "http://api.example.com/FUZZ", "-w", "/usr/share/wordlists/api/api-endpoints.txt",
        "-mc", "200,201,202,204,301,302,307,401,403,405", "-t", "50",
    ]

