# Browser Agent Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `BrowserAgent` (legacy `d689933:hexstrike_server.py:13623-14039`) into a new `hexstrike/tools/browser.py`, registering 4 of its actions as 4 independent tools under the existing `webtest` category (created by the http_framework migration, PR #14): `browser_navigate`, `browser_screenshot`, `browser_close`, `browser_status`. Extends `webtest` from 7 to 11 tools.

**Architecture:** `BrowserAgent` is ported as a class holding a live Selenium `webdriver.Chrome` instance that persists across separate tool calls (`navigate` → `screenshot` → `close` are three separate tool invocations sharing one browser session) — the second stateful singleton in this project, following the exact same pattern `HTTPTestingFramework` established: a module-level singleton `_browser_agent = BrowserAgent()`, a test-only `reset()` method, thin tool-function wrappers. Chromium and chromedriver are both installed in this environment (`/usr/bin/chromium`, `/usr/bin/chromedriver`, confirmed working with Selenium 4.49.0 already installed via `requirements.txt`) — Selenium resolves `chromedriver` from `PATH` automatically, no explicit `Service(executable_path=...)` needed, matching legacy's bare `webdriver.Chrome(options=chrome_options)`.

**Tech Stack:** Python 3.13, pytest, `selenium` (already a dependency, first real use in the modular codebase), `requests` (already used by `http_framework.py`, reused here for `_analyze_security_headers`/`run_active_tests`'s lightweight HTTP probes).

**Spec:** `docs/superpowers/specs/2026-09-10-webtest-tools-design.md` (Group D design, approved). Source-of-truth for original class/tool behavior: `git show d689933:hexstrike_server.py`.

## Global Constraints

- **No new category** — all 4 tools register under the existing `webtest` category (already created by `hexstrike/tools/http_framework.py`).
- **Exception-handling normalization (style only, no behavior change)**: legacy's several bare `except:` clauses in the extraction/storage helpers (`_get_local_storage`, `_get_session_storage`, `_extract_forms`, `_extract_links`, `_extract_inputs`, `_extract_scripts`, `_get_network_logs`, `_get_console_errors`, `_analyze_cookies`'s caller-adjacent helpers) become `except Exception:` — this only changes behavior for `KeyboardInterrupt`/`SystemExit`, never the intent of the original bare catch. Same normalization already applied to `gdb_analyze`'s temp-file cleanup in the binary-tools-migration plan.
- **Browser lifecycle preserved exactly**:
  - `browser_navigate`: if `_browser_agent.driver is None`, lazily calls `setup_browser()` first (auto-init on first navigate) — matches legacy's `if not self.driver: if not self.setup_browser(): return {'success': False, 'error': 'Failed to setup browser'}` inside `navigate_and_inspect` itself (not duplicated at the tool-function level).
  - `browser_screenshot`: returns an error ("Browser not initialized. Use navigate action first.") if `driver is None` — no lazy init here, this check lives in the TOOL function (legacy's Flask route did this check, not `BrowserAgent` itself — there is no `take_screenshot` method on the class; the endpoint used `browser_agent.driver.save_screenshot(...)` directly).
  - `browser_close`: no-op if `driver` is already `None` (legacy's `if self.driver:` guard prevents calling `.quit()` on nothing).
  - `browser_status`: reports `driver is not None`, `len(screenshots)`, `len(page_sources)` — never errors, no driver required.
- **`reset()` is test-only** (mirrors `HTTPTestingFramework.reset()`): clears `screenshots`, `page_sources`, `network_logs`, and calls `close_browser()` if a driver exists (to avoid leaking real Chrome processes across test runs). No production tool function calls it.
- **Error handling stays inside the class**, not just at the tool-function level — `navigate_and_inspect` wraps its whole body in `try/except Exception as e: return {'success': False, 'error': str(e)}`, matching legacy and the same pattern already used throughout `http_framework.py`.
- **Screenshot path format preserved exactly**: `f"/tmp/hexstrike_screenshot_{int(time.time())}.png"`, used both inside `navigate_and_inspect` and in the `browser_screenshot` tool function — needs `import time`.
- **The `avoid_addresses`-style "preserve legacy quirks verbatim" principle applies here too**: `_analyze_page_security`'s CSRF check (`has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower() for input_data in form['inputs'])`) and `_extract_forms`' page-source-vs-Selenium-element duality (this class re-extracts forms via live `self.driver.find_elements`, NOT by re-parsing `page_source` with BeautifulSoup like `http_framework.py`'s `spider_website` does) are legacy's actual, intentional design — do not "fix" the duplication of logic between the two classes; they are legitimately different extraction mechanisms (`HTTPTestingFramework.spider_website` parses static HTML via BeautifulSoup since it never renders JS; `BrowserAgent` queries the live, JS-rendered DOM via Selenium).
- **Testing strategy** (per spec): ONE real, non-mocked integration test drives actual `chromium`/`chromedriver` for the full `setup_browser` → `navigate_and_inspect` → `close_browser` lifecycle against a small local HTML fixture, proving the real Selenium wiring works end-to-end (mirrors `tests/test_process.py` running real subprocess commands rather than mocking `subprocess.run`). Every other test — all 4 registered tool functions, and each extraction/analysis helper method in isolation — mocks either a fake `self.driver` object or `requests`, never launches a real browser.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: Module skeleton — `BrowserAgent.__init__`/`reset()`/`setup_browser`/`close_browser`, singleton, `browser_close`/`browser_status` tools

**Files:**
- Create: `hexstrike/tools/browser.py`
- Modify: `hexstrike/tools/__init__.py` (add `browser` to the import line)
- Test: `tests/test_browser_agent.py` (create file)

**Interfaces:**
- Produces: `BrowserAgent` class with `__init__`, `reset()`, `setup_browser(headless=True, proxy_port=None) -> bool`, `close_browser()`; module-level `_browser_agent = BrowserAgent()`; tools `browser_close()` at `/api/tools/browser-agent/close`, `browser_status()` at `/api/tools/browser-agent/status`, both category `"webtest"`.

**Legacy (`d689933:hexstrike_server.py:13627-13664, 14026-14032`):**
```python
def __init__(self):
    self.driver = None
    self.screenshots = []
    self.page_sources = []
    self.network_logs = []

def setup_browser(self, headless: bool = True, proxy_port: int = None):
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
    except Exception as e:
        return False

def close_browser(self):
    if self.driver:
        self.driver.quit()
        self.driver = None
```

(`logger.*` calls dropped throughout this plan, same as every prior migration — presentation-only, orthogonal to behavior.)

- [ ] **Step 1: Write the failing test**

Read `hexstrike/tools/__init__.py` first to see its current import line before editing it in Step 3.

Create `tests/test_browser_agent.py`:

```python
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
```

Note: `Options().arguments` is a real Selenium API (a plain list) — no need to mock `Options` itself, only `webdriver.Chrome`. `Options().to_capabilities()` includes `goog:loggingPrefs` once `set_capability` is called — the capability-check line in the first test is best-effort/illustrative; if it proves brittle against the installed Selenium version, it is acceptable to drop that one assertion and keep the `arguments` list checks, which are the load-bearing part of this test.

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_browser_agent.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hexstrike.tools.browser'`.

- [ ] **Step 3: Write minimal implementation**

Create `hexstrike/tools/browser.py`:

```python
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
```

Update `hexstrike/tools/__init__.py` to add `browser` to the existing import line.

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port browser_agent skeleton, close/status tools`)

---

### Task 2: DOM/storage extraction helpers

**Files:**
- Modify: `hexstrike/tools/browser.py`
- Test: `tests/test_browser_agent.py`

**Interfaces:**
- Produces: `_get_local_storage() -> dict`, `_get_session_storage() -> dict`, `_extract_forms() -> list`, `_extract_links() -> list`, `_extract_inputs() -> list`, `_extract_scripts() -> list`, `_get_network_logs() -> list`, `_get_console_errors() -> list` — all consumed by `navigate_and_inspect` in Task 6.

**Legacy (`d689933:hexstrike_server.py:13746-13750, 13894-13985`):** each method queries `self.driver` (via `execute_script`, `find_elements(By.TAG_NAME, ...)`, or `get_log(...)`) and swallows any exception with a safe empty-collection fallback (bare `except:` in legacy, `except Exception:` here per Global Constraints).

- [ ] **Step 1: Write the failing test**

```python
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


def test_get_local_storage_returns_script_result():
    _browser_agent.driver = _FakeDriverWithElements(script_results={"localStorage": {"token": "abc"}})
    assert _browser_agent._get_local_storage() == {"token": "abc"}


def test_get_local_storage_returns_empty_on_exception():
    class _RaisingDriver:
        def execute_script(self, script):
            raise Exception("boom")
    _browser_agent.driver = _RaisingDriver()
    assert _browser_agent._get_local_storage() == {}


def test_get_session_storage_returns_script_result():
    _browser_agent.driver = _FakeDriverWithElements(script_results={"sessionStorage": {"csrf": "xyz"}})
    assert _browser_agent._get_session_storage() == {"csrf": "xyz"}


def test_extract_forms_from_elements():
    form_elem = _FakeElement(attrs={"action": "/submit", "method": "POST"})
    input_elem = _FakeElement(attrs={"name": "username", "type": "text", "value": ""})

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
    _browser_agent.driver = _RaisingDriver()
    assert _browser_agent._get_console_errors() == []
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add `from selenium.webdriver.common.by import By` and `import json` to `hexstrike/tools/browser.py`'s imports:

```python
    def _get_console_errors(self) -> list:
        try:
            logs = self.driver.get_log('browser')
            out = []
            for entry in logs[-100:]:
                lvl = entry.get('level', '')
                if lvl in ('SEVERE', 'WARNING'):
                    out.append({'level': lvl, 'message': entry.get('message', '')[:500]})
            return out
        except Exception:
            return []

    def _get_local_storage(self) -> dict:
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
        except Exception:
            return {}

    def _get_session_storage(self) -> dict:
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
        except Exception:
            return {}

    def _extract_forms(self) -> list:
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }
                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })
                forms.append(form_data)
        except Exception:
            pass
        return forms

    def _extract_links(self) -> list:
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in link_elements[:50]:
                href = link.get_attribute('href')
                if href:
                    links.append({'href': href, 'text': link.text[:100]})
        except Exception:
            pass
        return links

    def _extract_inputs(self) -> list:
        inputs = []
        try:
            input_elements = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
        except Exception:
            pass
        return inputs

    def _extract_scripts(self) -> list:
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in script_elements[:20]:
                src = script.get_attribute('src')
                if src:
                    scripts.append({'type': 'external', 'src': src})
                else:
                    content = script.get_attribute('innerHTML')
                    if content and len(content) > 10:
                        scripts.append({'type': 'inline', 'content': content[:1000]})
        except Exception:
            pass
        return scripts

    def _get_network_logs(self) -> list:
        try:
            logs = self.driver.get_log('performance')
            network_requests = []
            for log in logs[-50:]:
                message = json.loads(log['message'])
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_requests.append({
                        'url': response['url'],
                        'status': response['status'],
                        'mimeType': response['mimeType'],
                        'headers': response.get('headers', {})
                    })
            return network_requests
        except Exception:
            return []
```

**Note on `_extract_forms`'s inner `form.find_elements(...)`**: legacy calls `.find_elements(By.TAG_NAME, 'input')` on the `form` WebElement itself (scoping the query to inside that form), not on `self.driver` — the test's `_FakeElement` needs a `find_elements` method too if a test exercises multiple inputs per form; the Step-1 test above defines `form_elem`/`input_elem` as separate top-level fakes and monkeypatches `_DriverWithForms.find_elements` to return `[input_elem]` regardless of caller for simplicity, which is a reasonable simplification for this single-input-per-form test case — a form-scoped `find_elements` fake is not required for this task's minimal coverage, but note it if extending coverage later.

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): add browser_agent DOM/storage extraction helpers`)

---

### Task 3: `_analyze_page_security`

**Files:**
- Modify: `hexstrike/tools/browser.py`
- Test: `tests/test_browser_agent.py`

**Interfaces:**
- Produces: `_analyze_page_security(page_source: str, page_info: dict) -> dict` — pure function of its two dict/string arguments, no `self.driver` access. Consumed by `navigate_and_inspect` in Task 6.

**Legacy (`d689933:hexstrike_server.py:13994-14026`):** checks `local_storage`/`session_storage` for sensitive-looking keys, flags POST forms with no CSRF-looking input name, counts inline scripts; returns `{'total_issues', 'issues', 'security_score'}` with `security_score = max(0, 100 - len(issues) * 10)`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
    def _analyze_page_security(self, page_source: str, page_info: dict) -> dict:
        issues = []

        for storage_type, storage_data in [('localStorage', page_info.get('local_storage', {})),
                                            ('sessionStorage', page_info.get('session_storage', {}))]:
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    issues.append({
                        'type': 'sensitive_data_storage',
                        'severity': 'high',
                        'description': f'Sensitive data found in {storage_type}: {key}',
                        'location': storage_type
                    })

        for form in page_info.get('forms', []):
            has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower()
                          for input_data in form['inputs'])
            if not has_csrf and form['method'].upper() == 'POST':
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'description': 'Form without CSRF protection detected',
                    'form_action': form['action']
                })

        inline_scripts = [s for s in page_info.get('scripts', []) if s['type'] == 'inline']
        if inline_scripts:
            issues.append({
                'type': 'inline_javascript',
                'severity': 'low',
                'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                'count': len(inline_scripts)
            })

        return {
            'total_issues': len(issues),
            'issues': issues,
            'security_score': max(0, 100 - (len(issues) * 10))
        }
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): add browser_agent page security analysis`)

---

### Task 4: Passive analysis — `_analyze_cookies`, `_analyze_security_headers`, `_detect_mixed_content`, `_extended_passive_analysis`

**Files:**
- Modify: `hexstrike/tools/browser.py`
- Test: `tests/test_browser_agent.py`

**Interfaces:**
- Produces: `_analyze_cookies(cookies: list) -> list`, `_analyze_security_headers(page_source: str, page_info: dict) -> list` (uses `requests.get`, mocked in tests), `_detect_mixed_content(page_info: dict) -> list`, `_extended_passive_analysis(page_info: dict, page_source: str) -> dict`. Consumed by `navigate_and_inspect` in Task 6.

**Legacy (`d689933:hexstrike_server.py:13756-13809`):** `_analyze_security_headers` does a *separate, lightweight* `requests.get(page_info.get('url',''), timeout=10, verify=False)` fetch (not via `self.driver`) purely to read response headers Selenium can't expose directly — this needs `import requests` in `browser.py` (a second, independent use of the `requests` library from what `http_framework.py` uses; each module keeps its own import, no cross-module sharing).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add `import requests` to `hexstrike/tools/browser.py`'s imports:

```python
    def _analyze_cookies(self, cookies: list) -> list:
        issues = []
        for ck in cookies:
            name = ck.get('name', '')
            if name.lower() in ('sessionid', 'phpsessid', 'jsessionid') and len(ck.get('value', '')) < 16:
                issues.append({'type': 'weak_session_cookie', 'severity': 'medium', 'description': f'Session cookie {name} appears short'})
        return issues

    def _analyze_security_headers(self, page_source: str, page_info: dict) -> list:
        issues = []
        try:
            resp = requests.get(page_info.get('url', ''), timeout=10, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            required = {
                'content-security-policy': 'CSP header missing (XSS mitigation)',
                'x-frame-options': 'X-Frame-Options missing (Clickjacking risk)',
                'x-content-type-options': 'X-Content-Type-Options missing (MIME sniffing risk)',
                'referrer-policy': 'Referrer-Policy missing (leaky referrers)',
                'strict-transport-security': 'HSTS missing (HTTPS downgrade risk)'
            }
            for key, desc in required.items():
                if key not in headers:
                    issues.append({'type': 'missing_security_header', 'severity': 'medium', 'description': desc, 'header': key})
            csp = headers.get('content-security-policy', '')
            if csp and "unsafe-inline" in csp:
                issues.append({'type': 'weak_csp', 'severity': 'low', 'description': 'CSP allows unsafe-inline scripts'})
        except Exception:
            pass
        return issues

    def _detect_mixed_content(self, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url', '')
            if page_url.startswith('https://'):
                for req in page_info.get('network_requests', [])[:200]:
                    u = req.get('url', '')
                    if u.startswith('http://'):
                        issues.append({'type': 'mixed_content', 'severity': 'medium', 'description': f'HTTP resource loaded over HTTPS page: {u[:100]}'})
        except Exception:
            pass
        return issues

    def _extended_passive_analysis(self, page_info: dict, page_source: str) -> dict:
        modules = []
        issues = []
        cookie_issues = self._analyze_cookies(page_info.get('cookies', []))
        if cookie_issues:
            issues.extend(cookie_issues); modules.append('cookie_analysis')
        header_issues = self._analyze_security_headers(page_source, page_info)
        if header_issues:
            issues.extend(header_issues); modules.append('security_headers')
        mixed = self._detect_mixed_content(page_info)
        if mixed:
            issues.extend(mixed); modules.append('mixed_content')
        if page_info.get('console_errors'):
            modules.append('console_log_capture')
        return {'issues': issues, 'modules': modules}
```

**Note on `_analyze_cookies`'s legacy typo**: legacy's source (`hexstrike_server.py:13759`) literally reads `'phpseSSID'` (mixed-case, not the conventional `'PHPSESSID'`) inside a tuple compared against an already-lowercased `name`. Since `name.lower() in ('sessionid', 'phpseSSID', 'jsessionid')` compares a lowercased string against a tuple containing one NOT-fully-lowercased entry, `'phpseSSID'` can never match anything (it's not equal to any possible output of `.lower()`), making that branch of the check permanently dead for PHP session cookies. This is a legacy bug. Per this project's "preserve quirks verbatim" precedent, this plan writes the corrected-lowercase `'phpsessid'` in the implementation above rather than reproducing the dead-code typo — **this is the one deliberate exception to verbatim-preservation in this plan**, on the grounds that reproducing an unreachable comparison serves no purpose (unlike e.g. `avoid_addresses`'s bug, which was reachable and observably changed behavior); if a stricter verbatim reading is preferred, use `'phpseSSID'` literally instead and note that the branch is intentionally unreachable, matching legacy exactly. Flag this choice in the commit message either way.

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): add browser_agent passive security analysis`)

---

### Task 5: `run_active_tests`

**Files:**
- Modify: `hexstrike/tools/browser.py`
- Test: `tests/test_browser_agent.py`

**Interfaces:**
- Produces: `run_active_tests(page_info: dict, payload: str = '<hexstrikeXSSTest123>') -> dict`. Consumed by `navigate_and_inspect` in Task 6 (only when the tool caller passes `active_tests=True`).

**Legacy (`d689933:hexstrike_server.py:13927-13957`):** for each GET form with text/search inputs (max 3 inputs, max 5 forms tested), builds a query-string test URL with the payload injected into each param, fetches it via `requests.get(..., verify=False)`, and flags reflection.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add `from urllib.parse import urljoin` to `hexstrike/tools/browser.py`'s imports (if not already present from another task):

```python
    def run_active_tests(self, page_info: dict, payload: str = '<hexstrikeXSSTest123>') -> dict:
        findings = []
        tested = 0
        for form in page_info.get('forms', []):
            if form.get('method', 'GET').upper() != 'GET':
                continue
            params = []
            for inp in form.get('inputs', [])[:3]:
                if inp.get('type', 'text') in ('text', 'search'):
                    params.append(f"{inp.get('name', 'param')}={payload}")
            if not params:
                continue
            action = form.get('action') or page_info.get('url', '')
            if action.startswith('/'):
                base = page_info.get('url', '')
                try:
                    action = urljoin(base, action)
                except Exception:
                    pass
            test_url = action + ('&' if '?' in action else '?') + '&'.join(params)
            try:
                r = requests.get(test_url, timeout=8, verify=False)
                tested += 1
                if payload in r.text:
                    findings.append({'type': 'reflected_xss', 'severity': 'high', 'description': 'Payload reflected in response', 'url': test_url})
            except Exception:
                continue
            if tested >= 5:
                break
        return {'active_findings': findings, 'tested_forms': tested}
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): add browser_agent active reflected-XSS testing`)

---

### Task 6: `navigate_and_inspect`, `browser_navigate` tool (includes the one real Chrome integration test)

**Files:**
- Modify: `hexstrike/tools/browser.py`
- Test: `tests/test_browser_agent.py`

**Interfaces:**
- Consumes: every method from Tasks 1-5 (`setup_browser`, `_get_local_storage`, `_get_session_storage`, `_extract_forms`, `_extract_links`, `_extract_inputs`, `_extract_scripts`, `_get_network_logs`, `_get_console_errors`, `_analyze_page_security`, `_extended_passive_analysis`, `run_active_tests`).
- Produces: `navigate_and_inspect(url: str, wait_time: int = 5) -> dict`; tool `browser_navigate(url, headless=True, wait_time=5, active_tests=False)` at `/api/tools/browser-agent/navigate`.

**Legacy (`d689933:hexstrike_server.py:13666-13712`):**
```python
def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
    try:
        if not self.driver:
            if not self.setup_browser():
                return {'success': False, 'error': 'Failed to setup browser'}
        self.driver.get(url)
        time.sleep(wait_time)
        screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
        self.driver.save_screenshot(screenshot_path)
        self.screenshots.append(screenshot_path)
        page_source = self.driver.page_source
        self.page_sources.append({'url': url, 'source': page_source[:50000], 'timestamp': datetime.now().isoformat()})
        page_info = {
            'title': self.driver.title, 'url': self.driver.current_url,
            'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']} for c in self.driver.get_cookies()],
            'local_storage': self._get_local_storage(), 'session_storage': self._get_session_storage(),
            'forms': self._extract_forms(), 'links': self._extract_links(), 'inputs': self._extract_inputs(),
            'scripts': self._extract_scripts(), 'network_requests': self._get_network_logs(), 'console_errors': self._get_console_errors()
        }
        security_analysis = self._analyze_page_security(page_source, page_info)
        extended_passive = self._extended_passive_analysis(page_info, page_source)
        security_analysis['issues'].extend(extended_passive['issues'])
        security_analysis['total_issues'] = len(security_analysis['issues'])
        security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
        security_analysis['passive_modules'] = extended_passive.get('modules', [])
        return {'success': True, 'page_info': page_info, 'security_analysis': security_analysis, 'screenshot': screenshot_path, 'timestamp': datetime.now().isoformat()}
    except Exception as e:
        return {'success': False, 'error': str(e)}
```

**Note the re-scored `security_score` after merging**: `navigate_and_inspect` recomputes `security_score` as `max(0, 100 - total_issues * 5)` (a `*5` multiplier) AFTER merging in the passive-analysis issues — this OVERWRITES `_analyze_page_security`'s own `*10`-multiplier score from Task 3. Both scores are real, intentional legacy behavior at different points in the pipeline; do not "deduplicate" them into one shared scoring function.

`browser_navigate`'s `headless` parameter (legacy: `params.get("headless", True)`) is only consulted when `self.driver` needs lazy setup — matches `if not browser_agent.driver: setup_success = browser_agent.setup_browser(headless, proxy_port)`. Legacy's `browser-agent` endpoint's `navigate` action ALSO accepts `proxy_port` for this lazy setup call (not present in `navigate_and_inspect`'s own signature) — thread it through at the tool-function level, matching legacy's endpoint code exactly:
```python
if not url: 400  # dropped per established precedent
if not browser_agent.driver:
    setup_success = browser_agent.setup_browser(headless, proxy_port)
    if not setup_success:
        return jsonify({"error": "Failed to setup browser"}), 500
result = browser_agent.navigate_and_inspect(url, wait_time)
if result.get("success") and active_tests:
    active_results = browser_agent.run_active_tests(result.get("page_info", {}))
    result["active_tests"] = active_results
return jsonify(result)
```

- [ ] **Step 1: Write the failing tests**

First, the **one real, non-mocked Selenium integration test** for this whole plan:

```python
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
        assert result["page_info"]["forms"][0]["method"] == "POST"
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
    _browser_agent.driver = _RaisingDriver()

    result = _browser_agent.navigate_and_inspect("http://example.com")
    assert result["success"] is False
    assert "navigation timeout" in result["error"]


def test_browser_navigate_handler_invocation_lazy_setup(monkeypatch):
    setup_calls = []

    def fake_setup_browser(headless=True, proxy_port=None):
        setup_calls.append((headless, proxy_port))
        _browser_agent.driver = object()
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
    assert res == {"error": "Failed to setup browser"}


def test_browser_navigate_handler_invocation_with_active_tests(monkeypatch):
    _browser_agent.driver = object()

    def fake_navigate_and_inspect(url, wait_time=5):
        return {"success": True, "page_info": {"forms": [{"action": "/s", "method": "GET", "inputs": [{"name": "q", "type": "text"}]}]}, "security_analysis": {}, "screenshot": "/tmp/x.png", "timestamp": "now"}

    def fake_run_active_tests(page_info):
        return {"active_findings": [{"type": "reflected_xss"}], "tested_forms": 1}

    monkeypatch.setattr(_browser_agent, "navigate_and_inspect", fake_navigate_and_inspect)
    monkeypatch.setattr(_browser_agent, "run_active_tests", fake_run_active_tests)

    tool = ToolRegistry.get("browser_navigate")
    res = tool.handler(url="http://example.com", active_tests=True)
    assert res["active_tests"]["tested_forms"] == 1
```

Note: `data:` URLs never set a real `<title>`, so `page_info["title"]` is `""` in the real-browser test — this is expected, real browser behavior, not a bug.

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add `import time` and `from datetime import datetime` to `hexstrike/tools/browser.py`'s imports:

```python
    def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
        try:
            if not self.driver:
                if not self.setup_browser():
                    return {'success': False, 'error': 'Failed to setup browser'}

            self.driver.get(url)
            time.sleep(wait_time)

            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            self.driver.save_screenshot(screenshot_path)
            self.screenshots.append(screenshot_path)

            page_source = self.driver.page_source
            self.page_sources.append({'url': url, 'source': page_source[:50000], 'timestamp': datetime.now().isoformat()})

            page_info = {
                'title': self.driver.title,
                'url': self.driver.current_url,
                'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']} for c in self.driver.get_cookies()],
                'local_storage': self._get_local_storage(),
                'session_storage': self._get_session_storage(),
                'forms': self._extract_forms(),
                'links': self._extract_links(),
                'inputs': self._extract_inputs(),
                'scripts': self._extract_scripts(),
                'network_requests': self._get_network_logs(),
                'console_errors': self._get_console_errors()
            }

            security_analysis = self._analyze_page_security(page_source, page_info)
            extended_passive = self._extended_passive_analysis(page_info, page_source)
            security_analysis['issues'].extend(extended_passive['issues'])
            security_analysis['total_issues'] = len(security_analysis['issues'])
            security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
            security_analysis['passive_modules'] = extended_passive.get('modules', [])

            return {
                'success': True,
                'page_info': page_info,
                'security_analysis': security_analysis,
                'screenshot': screenshot_path,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
```

```python
@ToolRegistry.register(
    name="browser_navigate",
    category="webtest",
    description="Navigate to a URL with a real browser and inspect the rendered page for security issues",
    endpoint="/api/tools/browser-agent/navigate"
)
def browser_navigate(url: str, headless: bool = True, wait_time: int = 5, proxy_port: Optional[int] = None, active_tests: bool = False) -> Dict[str, Any]:
    if not _browser_agent.driver:
        setup_success = _browser_agent.setup_browser(headless, proxy_port)
        if not setup_success:
            return {"error": "Failed to setup browser"}
    result = _browser_agent.navigate_and_inspect(url, wait_time)
    if result.get("success") and active_tests:
        active_results = _browser_agent.run_active_tests(result.get("page_info", {}))
        result["active_tests"] = active_results
    return result
```

- [ ] **Step 4: Run test to verify it passes**

The real-browser test will take longer than the mocked tests (launching a real headless Chrome process) — this is expected and acceptable for the one test in this plan that needs it.

- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port navigate_and_inspect and browser_navigate tool`)

---

### Task 7: `browser_screenshot` tool

**Files:**
- Modify: `hexstrike/tools/browser.py`
- Test: `tests/test_browser_agent.py`

**Interfaces:**
- Produces: `browser_screenshot()` at `/api/tools/browser-agent/screenshot`, no parameters.

**Legacy (`d689933:hexstrike_server.py:14184-14200`):**
```python
elif action == "screenshot":
    if not browser_agent.driver:
        return jsonify({"error": "Browser not initialized. Use navigate action first."}), 400
    screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
    browser_agent.driver.save_screenshot(screenshot_path)
    return jsonify({
        "success": True,
        "screenshot": screenshot_path,
        "current_url": browser_agent.driver.current_url,
        "timestamp": datetime.now().isoformat(),
    })
```

Note: unlike `navigate_and_inspect`, this endpoint does NOT append to `self.screenshots` — legacy's screenshot action calls `driver.save_screenshot` directly without going through the class's own screenshot-tracking list. Preserve this exactly (a `browser_status` call after a bare `browser_screenshot` will NOT show the incremented `screenshots_taken` count — this is legacy's actual behavior, not a bug to fix).

- [ ] **Step 1: Write the failing test**

```python
def test_browser_screenshot_handler_invocation_no_driver():
    _browser_agent.driver = None
    tool = ToolRegistry.get("browser_screenshot")
    assert tool is not None
    assert tool.endpoint == "/api/tools/browser-agent/screenshot"

    res = tool.handler()
    assert res == {"error": "Browser not initialized. Use navigate action first."}


def test_browser_screenshot_handler_invocation_with_driver():
    class _FakeDriverForScreenshot:
        current_url = "http://example.com/page"

        def save_screenshot(self, path):
            self.saved_path = path

    fake = _FakeDriverForScreenshot()
    _browser_agent.driver = fake

    tool = ToolRegistry.get("browser_screenshot")
    res = tool.handler()
    assert res["success"] is True
    assert res["screenshot"].startswith("/tmp/hexstrike_screenshot_")
    assert res["current_url"] == "http://example.com/page"
    assert fake.saved_path == res["screenshot"]
    assert _browser_agent.screenshots == []  # not tracked, matching legacy
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="browser_screenshot",
    category="webtest",
    description="Capture a screenshot of the current page in the active browser session",
    endpoint="/api/tools/browser-agent/screenshot"
)
def browser_screenshot() -> Dict[str, Any]:
    if not _browser_agent.driver:
        return {"error": "Browser not initialized. Use navigate action first."}
    screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
    _browser_agent.driver.save_screenshot(screenshot_path)
    return {
        "success": True,
        "screenshot": screenshot_path,
        "current_url": _browser_agent.driver.current_url,
        "timestamp": datetime.now().isoformat(),
    }
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port browser_screenshot tool`)

---

### Task 8: Full verification

**Files:** none created/modified beyond one test addition.

- [ ] **Step 1: Assert `webtest` category has exactly 11 tools**

Add to `tests/test_browser_agent.py`:

```python
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
```

- [ ] **Step 2: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all PASS. Note this run will be noticeably slower than prior plans' full-suite runs due to Task 6's one real Chrome launch — this is expected.

- [ ] **Step 3: Sanity-check the MCP layer picks up the new tools**

```bash
./.venv/bin/python3 -c "
import asyncio
from hexstrike.mcp.client import HexStrikeClient
from hexstrike.mcp.server import setup_mcp_server

client = HexStrikeClient(server_url='http://127.0.0.1:8888')
mcp = setup_mcp_server(client)

async def main():
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert 'browser_navigate' in names
    assert 'browser_screenshot' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_browser_agent.py
git commit -m "$(cat <<'EOF'
test(tools): verify webtest category reaches 11-tool parity (browser_agent)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```
