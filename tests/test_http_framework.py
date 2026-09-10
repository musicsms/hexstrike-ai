import pytest
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

    _http_framework.reset()

    assert _http_framework.proxy_history == []
    assert _http_framework.vulnerabilities == []
    assert _http_framework.match_replace_rules == []
    assert _http_framework.scope is None
    assert _http_framework._req_id == 0


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
