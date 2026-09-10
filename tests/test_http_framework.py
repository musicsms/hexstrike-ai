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
