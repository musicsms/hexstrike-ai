import pytest
from hexstrike.tools.http_framework import _http_framework
from hexstrike.tools.browser import _browser_agent


@pytest.fixture(autouse=True)
def _reset_webtest_singletons():
    """Test-only: clear HTTPTestingFramework/BrowserAgent state before and after
    every test in the suite, so one test's accumulated proxy history, cookies,
    or live browser session never leaks into another. A no-op for tests that
    never touch these singletons."""
    _http_framework.reset()
    _browser_agent.reset()
    yield
    _http_framework.reset()
    _browser_agent.reset()
