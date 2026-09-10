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
