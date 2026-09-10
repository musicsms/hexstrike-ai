import pytest
import requests
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools
from hexstrike.tools.http_framework import _http_framework


@pytest.fixture(autouse=True)
def _reset_http_framework():
    _http_framework.reset()
    yield
    _http_framework.reset()


def test_http_framework_set_scope_handler_invocation():
    tool = ToolRegistry.get("http_framework_set_scope")
    assert tool is not None
    assert tool.category == "webtest"
    assert tool.endpoint == "/api/tools/http-framework/set-scope"

    res = tool.handler(host="example.com", include_subdomains=False)
    assert res == {"success": True, "scope": {"host": "example.com", "include_subdomains": False}}
    assert _http_framework.scope == {"host": "example.com", "include_subdomains": False}


def test_http_framework_set_rules_handler_invocation():
    tool = ToolRegistry.get("http_framework_set_rules")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/set-rules"

    rules = [{"where": "url", "pattern": "http://", "replacement": "https://"}]
    res = tool.handler(rules=rules)
    assert res == {"success": True, "rules_set": 1}
    assert _http_framework.match_replace_rules == rules


def test_http_framework_set_rules_handler_invocation_no_rules():
    tool = ToolRegistry.get("http_framework_set_rules")
    res = tool.handler()
    assert res == {"success": True, "rules_set": 0}
    assert _http_framework.match_replace_rules == []


def test_reset_clears_all_mutable_state():
    _http_framework.proxy_history.append({"fake": "entry"})
    _http_framework.vulnerabilities.append({"fake": "vuln"})
    _http_framework.match_replace_rules.append({"fake": "rule"})
    _http_framework.scope = {"host": "example.com", "include_subdomains": True}
    _http_framework._req_id = 5
    _http_framework.session.cookies.set("sid", "leaked")
    _http_framework.session.headers.update({"Authorization": "Bearer secret"})

    _http_framework.reset()

    assert _http_framework.proxy_history == []
    assert _http_framework.vulnerabilities == []
    assert _http_framework.match_replace_rules == []
    assert _http_framework.scope is None
    assert _http_framework._req_id == 0
    assert "sid" not in _http_framework.session.cookies
    assert "Authorization" not in _http_framework.session.headers


def test_in_scope_no_scope_set_allows_everything():
    assert _http_framework._in_scope("http://anything.example.org/") is True


def test_in_scope_exact_host_match():
    _http_framework.set_scope("example.com", include_subdomains=False)
    assert _http_framework._in_scope("http://example.com/path") is True
    assert _http_framework._in_scope("http://other.com/path") is False


def test_in_scope_subdomain_match():
    _http_framework.set_scope("example.com", include_subdomains=True)
    assert _http_framework._in_scope("http://api.example.com/path") is True
    _http_framework.set_scope("example.com", include_subdomains=False)
    assert _http_framework._in_scope("http://api.example.com/path") is False


def test_apply_match_replace_url_rule():
    _http_framework.set_match_replace_rules([{"where": "url", "pattern": "http://", "replacement": "https://"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", {}, {})
    assert url == "https://example.com/"


def test_apply_match_replace_query_rule():
    _http_framework.set_match_replace_rules([{"where": "query", "pattern": "old", "replacement": "new"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/?old=old_value", {}, {})
    assert url == "http://example.com/?new=new_value"


def test_apply_match_replace_headers_rule():
    _http_framework.set_match_replace_rules([{"where": "headers", "pattern": "SECRET", "replacement": "REDACTED"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", {}, {"X-SECRET": "value"})
    assert headers == {"X-REDACTED": "value"}


def test_apply_match_replace_body_dict_rule():
    _http_framework.set_match_replace_rules([{"where": "body", "pattern": "foo", "replacement": "bar"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", {"foo": "foo_val"}, {})
    assert data == {"bar": "bar_val"}


def test_apply_match_replace_body_string_rule():
    _http_framework.set_match_replace_rules([{"where": "body", "pattern": "foo", "replacement": "bar"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", "foo=1", {})
    assert data == "bar=1"


def test_apply_match_replace_out_of_scope_reverts_to_original():
    _http_framework.set_scope("allowed.com", include_subdomains=False)
    _http_framework.set_match_replace_rules([{"where": "url", "pattern": "allowed.com", "replacement": "blocked.com"}])
    url, data, headers = _http_framework._apply_match_replace("http://allowed.com/", {"a": 1}, {"h": "v"})
    assert url == "http://allowed.com/"
    assert data == {"a": 1}
    assert headers == {"h": "v"}


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", elapsed_seconds=0.1):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()

        class _Elapsed:
            def total_seconds(_self):
                return elapsed_seconds
        self.elapsed = _Elapsed()

        class _Request:
            def __init__(_self):
                _self.headers = {}
        self.request = _Request()


def test_intercept_request_success_records_history(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="hello world")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    assert tool is not None
    assert tool.category == "webtest"
    assert tool.endpoint == "/api/tools/http-framework/request"

    res = tool.handler(url="http://example.com/")
    assert res["success"] is True
    assert res["response"]["status_code"] == 200
    assert len(_http_framework.proxy_history) == 1
    assert _http_framework.proxy_history[0]["response"]["content"] == "hello world"


def test_intercept_request_flags_missing_security_headers(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={}, text="hello")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/")
    vuln_types = {v["type"] for v in res["vulnerabilities"]}
    assert vuln_types == {"missing_security_header"}
    assert len(res["vulnerabilities"]) == 5
    assert all(v["severity"] == "medium" for v in res["vulnerabilities"])


def test_intercept_request_flags_sensitive_data_disclosure(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="password: hunter2")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/")
    vuln_types = {v["type"] for v in res["vulnerabilities"]}
    assert "information_disclosure" in vuln_types


def test_intercept_request_flags_sql_error_indicator(monkeypatch):
    fake_response = _FakeResponse(status_code=500, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="You have an error in your SQL syntax error near line 1")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/")
    vuln_types = {v["type"] for v in res["vulnerabilities"]}
    assert "sql_injection_indicator" in vuln_types


def test_intercept_request_post_method_dispatch(monkeypatch):
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        return _FakeResponse(status_code=201, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="created")

    monkeypatch.setattr(_http_framework.session, "post", fake_post)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/create", method="POST", data={"name": "x"})
    assert res["success"] is True
    assert captured["url"] == "http://example.com/create"
    assert captured["data"] == {"name": "x"}


def test_intercept_request_failure_returns_error(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=None):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://unreachable.example.com/")
    assert res["success"] is False
    assert "refused" in res["error"]


def test_http_framework_proxy_history_handler_invocation_empty():
    tool = ToolRegistry.get("http_framework_proxy_history")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/proxy-history"

    res = tool.handler()
    assert res == {"success": True, "history": [], "total_requests": 0, "vulnerabilities": []}


def test_http_framework_proxy_history_handler_invocation_after_requests(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="ok")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    request_tool = ToolRegistry.get("http_framework_request")
    request_tool.handler(url="http://example.com/a")
    request_tool.handler(url="http://example.com/b")

    tool = ToolRegistry.get("http_framework_proxy_history")
    res = tool.handler()
    assert res["total_requests"] == 2
    assert len(res["history"]) == 2


def test_http_framework_repeater_handler_invocation(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        return _FakeResponse(status_code=200, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="ok")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_repeater")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/repeater"

    res = tool.handler(request={"url": "http://example.com/repeat", "method": "GET"})
    assert res["success"] is True
    assert captured["url"] == "http://example.com/repeat"


def test_http_framework_repeater_handler_invocation_no_request():
    tool = ToolRegistry.get("http_framework_repeater")
    res = tool.handler()
    assert res["success"] is False


def test_http_framework_intruder_handler_invocation_detects_reflection(monkeypatch):
    call_count = {"n": 0}

    def fake_get(url, params=None, headers=None, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # baseline request
            return _FakeResponse(status_code=200, headers={
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
                "Content-Security-Policy": "default-src 'self'",
            }, text="normal page")
        # fuzzed request reflects the payload
        return _FakeResponse(status_code=200, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="reflected: PAYLOAD_MARKER")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_intruder")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/intruder"

    res = tool.handler(url="http://example.com/search", params=["q"], payloads=["PAYLOAD_MARKER"])
    assert res["success"] is True
    assert res["tested"] == 1
    assert len(res["interesting"]) == 1
    assert res["interesting"][0]["reflected"] is True


def test_http_framework_intruder_handler_invocation_no_findings(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=None):
        return _FakeResponse(status_code=200, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="unchanged page")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_intruder")
    res = tool.handler(url="http://example.com/search", params=["q"], payloads=["harmless"])
    assert res["tested"] == 1
    assert res["interesting"] == []


_SAMPLE_HTML = """
<html><body>
<a href="/page2">Page 2</a>
<a href="https://external.example.org/other">External</a>
<form action="/submit" method="POST">
    <input name="username" type="text" value="">
    <input name="password" type="password" value="">
</form>
</body></html>
"""


def test_http_framework_spider_handler_invocation(monkeypatch):
    def fake_get(url, timeout=None):
        if url == "http://example.com/":
            return _FakeResponse(status_code=200, text=_SAMPLE_HTML)
        return _FakeResponse(status_code=200, text="<html><body>no links</body></html>")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_spider")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/spider"

    res = tool.handler(url="http://example.com/", max_depth=1, max_pages=10)
    assert res["success"] is True
    assert "http://example.com/" in res["discovered_urls"]
    assert "http://example.com/page2" in res["discovered_urls"]
    assert not any("external.example.org" in u for u in res["discovered_urls"])
    assert len(res["forms"]) == 1
    assert res["forms"][0]["method"] == "POST"
    assert {i["name"] for i in res["forms"][0]["inputs"]} == {"username", "password"}


def test_http_framework_spider_handler_invocation_respects_max_pages(monkeypatch):
    def fake_get(url, timeout=None):
        return _FakeResponse(status_code=200, text='<html><body><a href="/next">next</a></body></html>')

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_spider")
    res = tool.handler(url="http://example.com/", max_depth=10, max_pages=1)
    assert res["total_pages"] <= 1

