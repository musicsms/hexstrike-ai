import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools
from hexstrike.tools.browser import _browser_agent


@pytest.fixture(autouse=True)
def _reset_browser_agent():
    _browser_agent.reset()
    yield
    _browser_agent.reset()


class _FakeDriver:
    def __init__(self):
        self.quit_called = False

    def quit(self):
        self.quit_called = True

    def set_page_load_timeout(self, timeout):
        pass


def test_setup_browser_builds_expected_chrome_options(monkeypatch):
    captured = {}

    def fake_chrome(options=None):
        captured["args"] = list(options.arguments)
        captured["caps"] = dict(getattr(options, "_caps", {}) or options.to_capabilities().get("goog:loggingPrefs", {}))
        return _FakeDriver()

    monkeypatch.setattr("hexstrike.tools.browser.webdriver.Chrome", fake_chrome)

    result = _browser_agent.setup_browser(headless=True, proxy_port=8080)
    assert result is True
    assert _browser_agent.driver is not None
    assert "--headless" in captured["args"]
    assert "--no-sandbox" in captured["args"]
    assert "--proxy-server=http://127.0.0.1:8080" in captured["args"]


def test_setup_browser_no_headless_omits_flag(monkeypatch):
    captured = {}

    def fake_chrome(options=None):
        captured["args"] = list(options.arguments)
        return _FakeDriver()

    monkeypatch.setattr("hexstrike.tools.browser.webdriver.Chrome", fake_chrome)

    result = _browser_agent.setup_browser(headless=False)
    assert result is True
    assert "--headless" not in captured["args"]


def test_setup_browser_failure_returns_false(monkeypatch):
    def fake_chrome(options=None):
        raise Exception("chrome not found")

    monkeypatch.setattr("hexstrike.tools.browser.webdriver.Chrome", fake_chrome)

    result = _browser_agent.setup_browser()
    assert result is False
    assert _browser_agent.driver is None


def test_close_browser_quits_and_clears_driver():
    fake = _FakeDriver()
    _browser_agent.driver = fake
    _browser_agent.close_browser()
    assert fake.quit_called is True
    assert _browser_agent.driver is None


def test_close_browser_noop_when_no_driver():
    _browser_agent.driver = None
    _browser_agent.close_browser()  # must not raise
    assert _browser_agent.driver is None


def test_browser_close_handler_invocation():
    tool = ToolRegistry.get("browser_close")
    assert tool is not None
    assert tool.category == "webtest"
    assert tool.endpoint == "/api/tools/browser-agent/close"

    fake = _FakeDriver()
    _browser_agent.driver = fake
    res = tool.handler()
    assert res == {"success": True, "message": "Browser closed successfully"}
    assert fake.quit_called is True
    assert _browser_agent.driver is None


def test_browser_status_handler_invocation_no_driver():
    tool = ToolRegistry.get("browser_status")
    assert tool is not None
    assert tool.endpoint == "/api/tools/browser-agent/status"

    res = tool.handler()
    assert res == {"success": True, "browser_active": False, "screenshots_taken": 0, "pages_visited": 0}


def test_browser_status_handler_invocation_with_driver():
    _browser_agent.driver = _FakeDriver()
    _browser_agent.screenshots.append("/tmp/fake1.png")
    _browser_agent.page_sources.append({"url": "http://example.com", "source": "", "timestamp": ""})

    tool = ToolRegistry.get("browser_status")
    res = tool.handler()
    assert res == {"success": True, "browser_active": True, "screenshots_taken": 1, "pages_visited": 1}


def test_reset_clears_state_and_closes_browser():
    fake = _FakeDriver()
    _browser_agent.driver = fake
    _browser_agent.screenshots.append("/tmp/fake1.png")
    _browser_agent.page_sources.append({"url": "x"})
    _browser_agent.network_logs.append({"url": "y"})

    _browser_agent.reset()

    assert fake.quit_called is True
    assert _browser_agent.driver is None
    assert _browser_agent.screenshots == []
    assert _browser_agent.page_sources == []
    assert _browser_agent.network_logs == []


class _FakeElement:
    def __init__(self, attrs=None, text=""):
        self._attrs = attrs or {}
        self.text = text

    def get_attribute(self, name):
        return self._attrs.get(name)


class _FakeDriverWithElements:
    def __init__(self, elements_by_tag=None, script_results=None, logs=None):
        self._elements_by_tag = elements_by_tag or {}
        self._script_results = script_results or {}
        self._logs = logs or {}

    def find_elements(self, by, tag):
        return self._elements_by_tag.get(tag, [])

    def execute_script(self, script):
        for key, value in self._script_results.items():
            if key in script:
                return value
        raise Exception("unrecognized script")

    def get_log(self, log_type):
        return self._logs.get(log_type, [])

    def quit(self):
        pass


def test_get_local_storage_returns_script_result():
    _browser_agent.driver = _FakeDriverWithElements(script_results={"localStorage": {"token": "abc"}})
    assert _browser_agent._get_local_storage() == {"token": "abc"}


def test_get_local_storage_returns_empty_on_exception():
    class _RaisingDriver:
        def execute_script(self, script):
            raise Exception("boom")
        def quit(self):
            pass
    _browser_agent.driver = _RaisingDriver()
    assert _browser_agent._get_local_storage() == {}


def test_get_session_storage_returns_script_result():
    _browser_agent.driver = _FakeDriverWithElements(script_results={"sessionStorage": {"csrf": "xyz"}})
    assert _browser_agent._get_session_storage() == {"csrf": "xyz"}


def test_extract_forms_from_elements():
    form_elem = _FakeElement(attrs={"action": "/submit", "method": "POST"})
    input_elem = _FakeElement(attrs={"name": "username", "type": "text", "value": ""})
    form_elem.find_elements = lambda by, tag: [input_elem]

    class _DriverWithForms(_FakeDriverWithElements):
        def find_elements(self, by, tag):
            if tag == "form":
                return [form_elem]
            if tag == "input":
                return [input_elem]
            return []

    _browser_agent.driver = _DriverWithForms()
    forms = _browser_agent._extract_forms()
    assert forms == [{"action": "/submit", "method": "POST", "inputs": [{"name": "username", "type": "text", "value": ""}]}]


def test_extract_links_limits_to_50():
    links = [_FakeElement(attrs={"href": f"http://example.com/{i}"}, text=f"link{i}") for i in range(60)]
    _browser_agent.driver = _FakeDriverWithElements(elements_by_tag={"a": links})
    result = _browser_agent._extract_links()
    assert len(result) == 50
    assert result[0] == {"href": "http://example.com/0", "text": "link0"}


def test_extract_links_skips_missing_href():
    links = [_FakeElement(attrs={}, text="no href"), _FakeElement(attrs={"href": "http://x.com"}, text="ok")]
    _browser_agent.driver = _FakeDriverWithElements(elements_by_tag={"a": links})
    result = _browser_agent._extract_links()
    assert result == [{"href": "http://x.com", "text": "ok"}]


def test_extract_inputs_from_elements():
    inputs = [_FakeElement(attrs={"name": "q", "type": "search", "id": "search-box", "placeholder": "Search..."})]
    _browser_agent.driver = _FakeDriverWithElements(elements_by_tag={"input": inputs})
    result = _browser_agent._extract_inputs()
    assert result == [{"name": "q", "type": "search", "id": "search-box", "placeholder": "Search..."}]


def test_extract_scripts_external_and_inline():
    external = _FakeElement(attrs={"src": "/app.js"})
    inline = _FakeElement(attrs={"innerHTML": "var x = 'a very long inline script body here';"})
    _browser_agent.driver = _FakeDriverWithElements(elements_by_tag={"script": [external, inline]})
    result = _browser_agent._extract_scripts()
    assert {"type": "external", "src": "/app.js"} in result
    assert any(s["type"] == "inline" for s in result)


def test_get_network_logs_parses_performance_entries():
    import json
    perf_log = {"message": json.dumps({
        "message": {
            "method": "Network.responseReceived",
            "params": {"response": {"url": "http://x.com/api", "status": 200, "mimeType": "application/json", "headers": {}}}
        }
    })}
    _browser_agent.driver = _FakeDriverWithElements(logs={"performance": [perf_log]})
    result = _browser_agent._get_network_logs()
    assert result == [{"url": "http://x.com/api", "status": 200, "mimeType": "application/json", "headers": {}}]


def test_get_network_logs_empty_on_exception():
    class _RaisingDriver:
        def get_log(self, log_type):
            raise Exception("no logs")
        def quit(self):
            pass
    _browser_agent.driver = _RaisingDriver()
    assert _browser_agent._get_network_logs() == []


def test_get_console_errors_filters_severe_and_warning():
    logs = [
        {"level": "SEVERE", "message": "uncaught error"},
        {"level": "INFO", "message": "just info"},
        {"level": "WARNING", "message": "a warning"},
    ]
    _browser_agent.driver = _FakeDriverWithElements(logs={"browser": logs})
    result = _browser_agent._get_console_errors()
    assert result == [{"level": "SEVERE", "message": "uncaught error"}, {"level": "WARNING", "message": "a warning"}]


def test_get_console_errors_empty_on_exception():
    class _RaisingDriver:
        def get_log(self, log_type):
            raise Exception("no logs")
        def quit(self):
            pass
    _browser_agent.driver = _RaisingDriver()
    assert _browser_agent._get_console_errors() == []


def test_analyze_page_security_flags_sensitive_storage_data():
    page_info = {
        "local_storage": {"auth_token": "secret123"},
        "session_storage": {},
        "forms": [],
        "scripts": [],
    }
    result = _browser_agent._analyze_page_security("<html></html>", page_info)
    issue_types = {i["type"] for i in result["issues"]}
    assert "sensitive_data_storage" in issue_types


def test_analyze_page_security_flags_post_form_without_csrf():
    page_info = {
        "local_storage": {}, "session_storage": {},
        "forms": [{"action": "/login", "method": "POST", "inputs": [{"name": "username", "type": "text", "value": ""}]}],
        "scripts": [],
    }
    result = _browser_agent._analyze_page_security("<html></html>", page_info)
    issue_types = {i["type"] for i in result["issues"]}
    assert "missing_csrf_protection" in issue_types


def test_analyze_page_security_no_csrf_flag_when_csrf_field_present():
    page_info = {
        "local_storage": {}, "session_storage": {},
        "forms": [{"action": "/login", "method": "POST", "inputs": [{"name": "csrf_token", "type": "hidden", "value": "x"}]}],
        "scripts": [],
    }
    result = _browser_agent._analyze_page_security("<html></html>", page_info)
    issue_types = {i["type"] for i in result["issues"]}
    assert "missing_csrf_protection" not in issue_types


def test_analyze_page_security_counts_inline_scripts_and_scores():
    page_info = {
        "local_storage": {}, "session_storage": {}, "forms": [],
        "scripts": [{"type": "inline", "content": "x"}, {"type": "inline", "content": "y"}, {"type": "external", "src": "/a.js"}],
    }
    result = _browser_agent._analyze_page_security("<html></html>", page_info)
    inline_issue = next(i for i in result["issues"] if i["type"] == "inline_javascript")
    assert inline_issue["count"] == 2
    assert result["total_issues"] == 1
    assert result["security_score"] == 90


def test_analyze_cookies_flags_short_session_cookie():
    cookies = [{"name": "sessionid", "value": "abc123"}]
    issues = _browser_agent._analyze_cookies(cookies)
    assert any(i["type"] == "weak_session_cookie" for i in issues)


def test_analyze_cookies_ignores_long_session_cookie():
    cookies = [{"name": "sessionid", "value": "a" * 32}]
    issues = _browser_agent._analyze_cookies(cookies)
    assert issues == []


def test_analyze_security_headers_flags_missing_headers(monkeypatch):
    class _FakeResponse:
        headers = {}

    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: _FakeResponse())

    issues = _browser_agent._analyze_security_headers("<html></html>", {"url": "http://example.com"})
    issue_types = {i["type"] for i in issues}
    assert "missing_security_header" in issue_types
    assert len(issues) == 5


def test_analyze_security_headers_flags_weak_csp(monkeypatch):
    class _FakeResponse:
        headers = {
            "content-security-policy": "default-src 'self' 'unsafe-inline'",
            "x-frame-options": "DENY", "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer", "strict-transport-security": "max-age=1",
        }

    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: _FakeResponse())

    issues = _browser_agent._analyze_security_headers("<html></html>", {"url": "http://example.com"})
    assert any(i["type"] == "weak_csp" for i in issues)


def test_analyze_security_headers_request_failure_returns_empty(monkeypatch):
    def fake_get(url, timeout=None, verify=None):
        raise Exception("connection refused")

    monkeypatch.setattr("hexstrike.tools.browser.requests.get", fake_get)

    issues = _browser_agent._analyze_security_headers("<html></html>", {"url": "http://unreachable.example.com"})
    assert issues == []


def test_detect_mixed_content_flags_http_resource_on_https_page():
    page_info = {"url": "https://example.com", "network_requests": [{"url": "http://insecure.example.com/img.png"}]}
    issues = _browser_agent._detect_mixed_content(page_info)
    assert any(i["type"] == "mixed_content" for i in issues)


def test_detect_mixed_content_no_issue_on_http_page():
    page_info = {"url": "http://example.com", "network_requests": [{"url": "http://other.com/img.png"}]}
    issues = _browser_agent._detect_mixed_content(page_info)
    assert issues == []


def test_extended_passive_analysis_aggregates_modules(monkeypatch):
    class _FakeResponse:
        headers = {}

    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: _FakeResponse())

    page_info = {
        "url": "https://example.com",
        "cookies": [{"name": "sessionid", "value": "short"}],
        "network_requests": [{"url": "http://insecure.example.com/x"}],
        "console_errors": [{"level": "SEVERE", "message": "err"}],
    }
    result = _browser_agent._extended_passive_analysis(page_info, "<html></html>")
    assert set(result["modules"]) == {"cookie_analysis", "security_headers", "mixed_content", "console_log_capture"}
    assert len(result["issues"]) > 0


def test_run_active_tests_detects_reflection(monkeypatch):
    class _FakeResponse:
        text = "Result: <hexstrikeXSSTest123>"

    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: _FakeResponse())

    page_info = {
        "url": "http://example.com/search",
        "forms": [{"action": "/search", "method": "GET", "inputs": [{"name": "q", "type": "text", "value": ""}]}],
    }
    result = _browser_agent.run_active_tests(page_info)
    assert result["tested_forms"] == 1
    assert len(result["active_findings"]) == 1
    assert result["active_findings"][0]["type"] == "reflected_xss"


def test_run_active_tests_skips_post_forms(monkeypatch):
    calls = []
    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: calls.append(url))

    page_info = {"url": "http://example.com", "forms": [{"action": "/x", "method": "POST", "inputs": [{"name": "q", "type": "text"}]}]}
    result = _browser_agent.run_active_tests(page_info)
    assert result == {"active_findings": [], "tested_forms": 0}
    assert calls == []


def test_run_active_tests_skips_forms_with_no_text_inputs(monkeypatch):
    calls = []
    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: calls.append(url))

    page_info = {"url": "http://example.com", "forms": [{"action": "/x", "method": "GET", "inputs": [{"name": "cb", "type": "checkbox"}]}]}
    result = _browser_agent.run_active_tests(page_info)
    assert result["tested_forms"] == 0
    assert calls == []


def test_run_active_tests_no_reflection_no_finding(monkeypatch):
    class _FakeResponse:
        text = "no reflection here"

    monkeypatch.setattr("hexstrike.tools.browser.requests.get", lambda url, timeout=None, verify=None: _FakeResponse())

    page_info = {"url": "http://example.com", "forms": [{"action": "/search", "method": "GET", "inputs": [{"name": "q", "type": "text"}]}]}
    result = _browser_agent.run_active_tests(page_info)
    assert result["active_findings"] == []
    assert result["tested_forms"] == 1


def test_navigate_and_inspect_real_browser_end_to_end():
    """The one real (non-mocked) Selenium test in this plan - proves the full
    setup -> navigate -> extract -> analyze -> close pipeline actually works
    against real chromium/chromedriver, not just mocked driver objects."""
    fixture_html = (
        "data:text/html,"
        "<html><body>"
        "<h1>Test Page</h1>"
        "<a href='http://example.com/link1'>Link 1</a>"
        "<form action='/submit' method='POST'>"
        "<input name='username' type='text' value=''>"
        "</form>"
        "<script>var inline_test_marker = 1;</script>"
        "</body></html>"
    )
    assert _browser_agent.setup_browser(headless=True) is True
    try:
        result = _browser_agent.navigate_and_inspect(fixture_html, wait_time=1)
        assert result["success"] is True
        assert result["page_info"]["title"] == ""
        assert len(result["page_info"]["forms"]) == 1
        # Real Chrome canonicalizes the HTMLFormElement.method IDL property to
        # lowercase ("post") per the HTML Living Standard, and Selenium 4.x's
        # get_attribute() returns the JS property value (not the literal HTML
        # attribute text) when a same-named property exists. This is real,
        # correct browser behavior (verified against actual chromedriver in
        # this environment), so the comparison here is case-insensitive.
        assert result["page_info"]["forms"][0]["method"].upper() == "POST"
        assert len(result["page_info"]["links"]) == 1
        assert "security_analysis" in result
        assert "total_issues" in result["security_analysis"]
        assert result["screenshot"].startswith("/tmp/hexstrike_screenshot_")
        import os
        assert os.path.exists(result["screenshot"])
        os.remove(result["screenshot"])
    finally:
        _browser_agent.close_browser()


def test_navigate_and_inspect_lazy_setup_failure_mocked(monkeypatch):
    def fake_setup_browser(headless=True, proxy_port=None):
        return False
    monkeypatch.setattr(_browser_agent, "setup_browser", fake_setup_browser)
    _browser_agent.driver = None

    result = _browser_agent.navigate_and_inspect("http://example.com")
    assert result == {"success": False, "error": "Failed to setup browser"}


def test_navigate_and_inspect_exception_returns_error_mocked(monkeypatch):
    class _RaisingDriver:
        def get(self, url):
            raise Exception("navigation timeout")

        def quit(self):
            pass
    _browser_agent.driver = _RaisingDriver()

    result = _browser_agent.navigate_and_inspect("http://example.com")
    assert result["success"] is False
    assert "navigation timeout" in result["error"]


class _FakeDriverHandle:
    def quit(self):
        pass


def test_browser_navigate_handler_invocation_lazy_setup(monkeypatch):
    setup_calls = []

    def fake_setup_browser(headless=True, proxy_port=None):
        setup_calls.append((headless, proxy_port))
        _browser_agent.driver = _FakeDriverHandle()
        return True

    def fake_navigate_and_inspect(url, wait_time=5):
        return {"success": True, "page_info": {"forms": []}, "security_analysis": {}, "screenshot": "/tmp/x.png", "timestamp": "now"}

    monkeypatch.setattr(_browser_agent, "setup_browser", fake_setup_browser)
    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", fake_navigate_and_inspect)
    _browser_agent.driver = None

    tool = ToolRegistry.get("browser_navigate")
    assert tool is not None
    assert tool.endpoint == "/api/tools/browser-agent/navigate"

    res = tool.handler(url="http://example.com", headless=False, wait_time=2)
    assert res["success"] is True
    assert setup_calls == [(False, None)]
    assert "active_tests" not in res


def test_browser_navigate_handler_invocation_setup_failure(monkeypatch):
    monkeypatch.setattr(_browser_agent, "setup_browser", lambda headless=True, proxy_port=None: False)
    _browser_agent.driver = None

    tool = ToolRegistry.get("browser_navigate")
    res = tool.handler(url="http://example.com")
    assert res == {"success": False, "error": "Failed to setup browser"}


def test_browser_navigate_handler_invocation_with_active_tests(monkeypatch):
    _browser_agent.driver = _FakeDriverHandle()

    def fake_navigate_and_inspect(url, wait_time=5):
        return {"success": True, "page_info": {"forms": [{"action": "/s", "method": "GET", "inputs": [{"name": "q", "type": "text"}]}]}, "security_analysis": {}, "screenshot": "/tmp/x.png", "timestamp": "now"}

    def fake_run_active_tests(page_info):
        return {"active_findings": [{"type": "reflected_xss"}], "tested_forms": 1}

    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", fake_navigate_and_inspect)
    monkeypatch.setattr(_browser_agent, "run_active_tests", fake_run_active_tests)

    tool = ToolRegistry.get("browser_navigate")
    res = tool.handler(url="http://example.com", active_tests=True)
    assert res["active_tests"]["tested_forms"] == 1


def test_browser_screenshot_handler_invocation_no_driver():
    _browser_agent.driver = None
    tool = ToolRegistry.get("browser_screenshot")
    assert tool is not None
    assert tool.endpoint == "/api/tools/browser-agent/screenshot"

    res = tool.handler()
    assert res == {"success": False, "error": "Browser not initialized. Use navigate action first."}


def test_browser_screenshot_handler_invocation_with_driver():
    class _FakeDriverForScreenshot:
        current_url = "http://example.com/page"

        def save_screenshot(self, path):
            self.saved_path = path

        def quit(self):
            pass

    fake = _FakeDriverForScreenshot()
    _browser_agent.driver = fake

    tool = ToolRegistry.get("browser_screenshot")
    res = tool.handler()
    assert res["success"] is True
    assert res["screenshot"].startswith("/tmp/hexstrike_screenshot_")
    assert res["current_url"] == "http://example.com/page"
    assert fake.saved_path == res["screenshot"]
    assert _browser_agent.screenshots == []  # not tracked, matching legacy


def test_webtest_category_has_11_tools():
    from hexstrike.core.registry import ToolRegistry
    webtest_tools = ToolRegistry.get_by_category("webtest")
    assert len(webtest_tools) == 11
    names = {t.name for t in webtest_tools}
    assert names == {
        "http_framework_request", "http_framework_spider", "http_framework_proxy_history",
        "http_framework_set_rules", "http_framework_set_scope", "http_framework_repeater",
        "http_framework_intruder",
        "browser_navigate", "browser_screenshot", "browser_close", "browser_status",
    }
