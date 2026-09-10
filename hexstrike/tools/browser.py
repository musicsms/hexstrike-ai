from typing import Dict, Any, List, Optional
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from hexstrike.core.registry import ToolRegistry


class BrowserAgent:
    """AI-powered browser agent for web application testing and inspection"""

    def __init__(self):
        self.driver = None
        self.screenshots: List[str] = []
        self.page_sources: List[Dict[str, Any]] = []
        self.network_logs: List[Dict[str, Any]] = []

    def reset(self):
        """Test-only: clear all accumulated state and close any real browser. Never called by production tool functions."""
        self.close_browser()
        self.screenshots = []
        self.page_sources = []
        self.network_logs = []

    def setup_browser(self, headless: bool = True, proxy_port: Optional[int] = None) -> bool:
        try:
            chrome_options = Options()
            if headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=HexStrike-BrowserAgent/1.0 (Security Testing)')
            chrome_options.add_argument('--enable-logging')
            chrome_options.add_argument('--log-level=0')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            if proxy_port:
                chrome_options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')
            chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            return True
        except Exception:
            return False

    def close_browser(self):
        if self.driver:
            self.driver.quit()
            self.driver = None


_browser_agent = BrowserAgent()


@ToolRegistry.register(
    name="browser_close",
    category="webtest",
    description="Close the active browser session",
    endpoint="/api/tools/browser-agent/close"
)
def browser_close() -> Dict[str, Any]:
    _browser_agent.close_browser()
    return {"success": True, "message": "Browser closed successfully"}


@ToolRegistry.register(
    name="browser_status",
    category="webtest",
    description="Report whether a browser session is active and basic session stats",
    endpoint="/api/tools/browser-agent/status"
)
def browser_status() -> Dict[str, Any]:
    return {
        "success": True,
        "browser_active": _browser_agent.driver is not None,
        "screenshots_taken": len(_browser_agent.screenshots),
        "pages_visited": len(_browser_agent.page_sources),
    }
