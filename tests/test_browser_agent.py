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
