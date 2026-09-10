import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools
from hexstrike.tools.http_framework import _http_framework
from hexstrike.tools.browser import _browser_agent


@pytest.fixture(autouse=True)
def _reset_singletons():
    _http_framework.reset()
    _browser_agent.reset()
    yield
    _http_framework.reset()
    _browser_agent.reset()


class _FakeDriverHandle:
    def quit(self):
        pass


def test_burpsuite_alternative_scan_comprehensive_runs_all_phases(monkeypatch):
    setup_calls = []
    close_calls = []

    def fake_setup_browser(headless=True, proxy_port=None):
        setup_calls.append(headless)
        _browser_agent.driver = _FakeDriverHandle()
        return True

    def fake_close_browser():
        close_calls.append(True)
        _browser_agent.driver = None

    def fake_navigate_and_inspect(url, wait_time=5):
        return {"success": True, "page_info": {"title": "Example"}, "security_analysis": {}}

    def fake_spider_website(base_url, max_depth=3, max_pages=100):
        return {"success": True, "discovered_urls": ["http://example.com/", "http://example.com/about"], "forms": []}

    def fake_intercept_request(url, method="GET", data=None, headers=None, cookies=None):
        _http_framework.vulnerabilities.append({"type": "missing_security_header", "severity": "medium"})
        return {"success": True, "vulnerabilities": []}

    monkeypatch.setattr(_browser_agent, "setup_browser", fake_setup_browser)
    monkeypatch.setattr(_browser_agent, "close_browser", fake_close_browser)
    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", fake_navigate_and_inspect)
    monkeypatch.setattr(_http_framework, "spider_website", fake_spider_website)
    monkeypatch.setattr(_http_framework, "intercept_request", fake_intercept_request)

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    assert tool is not None
    assert tool.category == "webtest"
    assert tool.endpoint == "/api/tools/burpsuite-alternative"

    res = tool.handler(target="http://example.com/", headless=False)
    assert res["success"] is True
    assert res["target"] == "http://example.com/"
    assert res["scan_type"] == "comprehensive"
    assert setup_calls == [False]
    assert res["browser_analysis"]["page_info"]["title"] == "Example"
    assert res["spider_analysis"]["discovered_urls"] == ["http://example.com/", "http://example.com/about"]
    assert res["vulnerability_analysis"]["tested_urls"] == 2
    assert res["vulnerability_analysis"]["total_vulnerabilities"] == 2
    assert res["summary"]["total_vulnerabilities"] == 2
    assert res["summary"]["vulnerability_breakdown"] == {"medium": 2}
    assert res["summary"]["pages_analyzed"] == 2
    assert res["summary"]["security_score"] == 90
    # browser was opened by this scan -> must be closed by this scan
    assert close_calls == [True]
    assert _browser_agent.driver is None


def test_burpsuite_alternative_scan_spider_only_skips_vuln_phase(monkeypatch):
    monkeypatch.setattr(_browser_agent, "setup_browser", lambda headless=True, proxy_port=None: (_browser_agent.__setattr__("driver", _FakeDriverHandle()), True)[1])
    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", lambda url, wait_time=5: {"success": True})
    monkeypatch.setattr(_browser_agent, "close_browser", lambda: _browser_agent.__setattr__("driver", None))
    monkeypatch.setattr(_http_framework, "spider_website", lambda base_url, max_depth=3, max_pages=100: {"success": True, "discovered_urls": ["http://example.com/"]})

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="spider")
    assert "browser_analysis" in res
    assert "spider_analysis" in res
    assert "vulnerability_analysis" not in res


def test_burpsuite_alternative_scan_active_only_runs_vuln_phase_against_target(monkeypatch):
    calls = []

    def fake_intercept_request(url, method="GET", data=None, headers=None, cookies=None):
        calls.append(url)
        return {"success": True}

    monkeypatch.setattr(_http_framework, "intercept_request", fake_intercept_request)

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="active")
    assert "browser_analysis" not in res
    assert "spider_analysis" not in res
    assert "vulnerability_analysis" in res
    assert calls == ["http://example.com/"]  # falls back to [target] with no spider_analysis


def test_burpsuite_alternative_scan_passive_runs_no_phases():
    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="passive")
    assert "browser_analysis" not in res
    assert "spider_analysis" not in res
    assert "vulnerability_analysis" not in res
    assert res["summary"] == {
        "total_vulnerabilities": 0,
        "vulnerability_breakdown": {},
        "pages_analyzed": 0,
        "security_score": 100,
    }


def test_burpsuite_alternative_scan_browser_setup_failure_records_error_and_continues(monkeypatch):
    # scan_type="spider" (not "comprehensive") deliberately: it exercises phases 1+2
    # only, so this test doesn't need to mock intercept_request (phase 3) at all -
    # using "comprehensive" here would let phase 3 call the REAL, unmocked
    # intercept_request against "http://example.com/", making a genuine network
    # call from a unit test.
    monkeypatch.setattr(_browser_agent, "setup_browser", lambda headless=True, proxy_port=None: False)
    monkeypatch.setattr(_http_framework, "spider_website", lambda base_url, max_depth=3, max_pages=100: {"success": True, "discovered_urls": [base_url]})

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="spider")
    assert res["browser_analysis"] == {"success": False, "error": "Failed to setup browser"}
    assert "spider_analysis" in res  # other phases still run
    assert _browser_agent.driver is None


def test_burpsuite_alternative_scan_preserves_preexisting_browser_session(monkeypatch):
    # scan_type="spider" deliberately (not "comprehensive"): this test only cares
    # about phase 1's reuse-vs-open logic; "comprehensive" would also run phase 3
    # and require mocking intercept_request for no reason relevant to this test.
    preexisting_driver = _FakeDriverHandle()
    _browser_agent.driver = preexisting_driver

    setup_calls = []
    close_calls = []
    monkeypatch.setattr(_browser_agent, "setup_browser", lambda headless=True, proxy_port=None: setup_calls.append(1))
    monkeypatch.setattr(_browser_agent, "close_browser", lambda: close_calls.append(1))
    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", lambda url, wait_time=5: {"success": True})
    monkeypatch.setattr(_http_framework, "spider_website", lambda base_url, max_depth=3, max_pages=100: {"success": True, "discovered_urls": [base_url]})

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    tool.handler(target="http://example.com/", scan_type="spider")

    # this scan reused an already-open session - must not call setup_browser or close_browser
    assert setup_calls == []
    assert close_calls == []
    assert _browser_agent.driver is preexisting_driver


def test_burpsuite_alternative_scan_exception_returns_error(monkeypatch):
    # scan_type="active" deliberately: it's the only scan_type that touches
    # neither the browser (phase 1) nor spider_website (phase 2), so this test
    # can make exactly one method raise (intercept_request, phase 3) without
    # needing to also mock setup_browser/navigate_and_inspect to avoid an
    # accidental real Chrome launch.
    def raise_error(*a, **kw):
        raise Exception("boom")
    monkeypatch.setattr(_http_framework, "intercept_request", raise_error)

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="active")
    assert res == {"success": False, "error": "boom"}


def test_burpsuite_alternative_scan_closes_browser_when_navigate_and_inspect_raises(monkeypatch):
    # scan_type="spider" deliberately (not "comprehensive"): this test only cares
    # about phase 1's cleanup-on-exception behavior; "comprehensive"/"active"
    # would also run phase 3 and require mocking intercept_request for no reason
    # relevant to this test.
    close_calls = []

    def fake_setup_browser(headless=True, proxy_port=None):
        _browser_agent.driver = _FakeDriverHandle()
        return True

    def fake_close_browser():
        close_calls.append(True)
        _browser_agent.driver = None

    def raise_error(url, wait_time=5):
        raise Exception("navigate boom")

    monkeypatch.setattr(_browser_agent, "setup_browser", fake_setup_browser)
    monkeypatch.setattr(_browser_agent, "close_browser", fake_close_browser)
    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", raise_error)

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="spider")

    # the scan reports failure, but the browser it opened must still be closed
    assert res == {"success": False, "error": "navigate boom"}
    assert close_calls == [True]
    assert _browser_agent.driver is None


def test_burpsuite_alternative_scan_survives_close_browser_failure(monkeypatch):
    # scan_type="spider" deliberately (not "comprehensive"): this test only cares
    # about phase 1's teardown; "comprehensive"/"active" would also run phase 3
    # and require mocking intercept_request for no reason relevant to this test.
    def fake_setup_browser(headless=True, proxy_port=None):
        _browser_agent.driver = _FakeDriverHandle()
        return True

    def fake_close_browser():
        # simulate a dead driver connection raising on teardown
        raise Exception("connection already closed")

    monkeypatch.setattr(_browser_agent, "setup_browser", fake_setup_browser)
    monkeypatch.setattr(_browser_agent, "close_browser", fake_close_browser)
    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", lambda url, wait_time=5: {"success": True})
    monkeypatch.setattr(_http_framework, "spider_website", lambda base_url, max_depth=3, max_pages=100: {"success": True, "discovered_urls": [base_url]})

    tool = ToolRegistry.get("burpsuite_alternative_scan")
    res = tool.handler(target="http://example.com/", scan_type="spider")

    # a teardown failure must not discard the completed scan result
    assert res["success"] is True
    assert "browser_analysis" in res
    assert "spider_analysis" in res
    assert "summary" in res
    # the singleton must not be left wedged pointing at a dead driver
    assert _browser_agent.driver is None


def test_webtest_category_has_12_tools():
    from hexstrike.core.registry import ToolRegistry
    webtest_tools = ToolRegistry.get_by_category("webtest")
    assert len(webtest_tools) == 12
    names = {t.name for t in webtest_tools}
    assert names == {
        "http_framework_request", "http_framework_spider", "http_framework_proxy_history",
        "http_framework_set_rules", "http_framework_set_scope", "http_framework_repeater",
        "http_framework_intruder",
        "browser_navigate", "browser_screenshot", "browser_close", "browser_status",
        "burpsuite_alternative_scan",
    }
