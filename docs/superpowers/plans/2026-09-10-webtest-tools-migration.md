# WebTest Orchestrator Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `burpsuite-alternative` (legacy `d689933:hexstrike_server.py:14224-14318`) into a new `hexstrike/tools/webtest.py`, registering `burpsuite_alternative_scan` as the 12th and final tool in the `webtest` category. This is the third and last PR of Group D.

**Architecture:** Unlike `http_framework.py` and `browser.py` (each owning its own class + singleton), `webtest.py` owns no state of its own — it imports both existing singletons (`_http_framework` from `hexstrike.tools.http_framework`, `_browser_agent` from `hexstrike.tools.browser`, both already merged) and orchestrates them together into one multi-phase scan, exactly matching legacy's `burpsuite_alternative` endpoint, with two deliberate, user-approved corrections (see Global Constraints).

**Tech Stack:** Python 3.13, pytest — no new dependencies; reuses both prior singletons' existing capabilities.

**Spec:** `docs/superpowers/specs/2026-09-10-webtest-tools-design.md` (Group D design, approved). Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`. Forward-looking notes that motivate this plan's two deviations: the browser-agent-tools-migration PR's final review (PR #15, merged) flagged that legacy's `burpsuite_alternative` leaks a Chrome process (never calls `close_browser()`) and silently discards `setup_browser`'s return value.

## Global Constraints

- **Legacy's exact multi-phase structure is preserved**: two SEPARATE `if scan_type in ['comprehensive', 'spider']:` blocks (one for browser recon, one for HTTP spidering) rather than one combined block — this is legacy's actual code shape, not an accident to consolidate. `scan_type='passive'` matches none of the three phase conditions (`['comprehensive','spider']` twice, `['comprehensive','active']` once) and legacy behavior for it is to run ZERO phases, producing only the final summary block over whatever `_http_framework.vulnerabilities` already contains from prior calls — preserve this exactly, it is not a bug.
- **Deviation 1 (user-approved): close the browser at the end of the scan, but ONLY if this scan itself opened it.** Legacy never calls `close_browser()`, leaking a Chrome process per scan. This plan tracks whether `setup_browser()` was actually invoked (and succeeded) by this specific call — if the caller had ALREADY set up a browser session before calling this tool (e.g. via a prior `browser_navigate` call, deliberately kept open for a follow-up `browser_screenshot`), this scan must NOT close a session it didn't open. Only a session this scan created gets torn down.
- **Deviation 2 (user-approved): check `setup_browser`'s return value.** Legacy calls `if not browser_agent.driver: browser_agent.setup_browser(headless)` and ignores the return value, so a failed setup falls through to `navigate_and_inspect`'s own internal lazy-retry (which uses a hardcoded default `headless=True`, silently discarding the caller's `headless` argument). This plan checks the return value: on failure, `results['browser_analysis']` records `{'success': False, 'error': 'Failed to setup browser'}` directly (matching the exact error shape `browser_navigate`/`navigate_and_inspect` already use elsewhere in this codebase) and `navigate_and_inspect` is never called — the browser phase fails cleanly instead of silently retrying with the wrong setting. The other phases (spider, vulnerability analysis) still run normally afterward, since a browser failure doesn't invalidate an HTTP-only spider/analysis pass.
- **No new category, no new singleton** — `webtest.py` imports `_http_framework` and `_browser_agent` from their existing modules; it does not instantiate anything itself.
- **Error handling**: unlike every other tool in `webtest.py`'s sibling modules, legacy's `burpsuite_alternative` wraps its ENTIRE body in one outer `try/except Exception as e: return {"error": f"Server error: {str(e)}"}, 500` — this plan's port follows the established project precedent (`browser_navigate`, `http_framework_request`, etc.) of including `"success": False` in that error dict too, consistent with this project's final-review-driven correction to the sibling `browser.py` PR.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: `burpsuite_alternative_scan`

**Files:**
- Create: `hexstrike/tools/webtest.py`
- Modify: `hexstrike/tools/__init__.py` (add `webtest` to the import line)
- Test: `tests/test_webtest_tools.py` (create file)

**Interfaces:**
- Consumes: `_http_framework` (from `hexstrike.tools.http_framework`) — `.spider_website(base_url, max_depth, max_pages)`, `.intercept_request(url)`, `.vulnerabilities` (list), `._get_recent_vulns(limit)`, `.reset()` (test-only). `_browser_agent` (from `hexstrike.tools.browser`) — `.driver`, `.setup_browser(headless) -> bool`, `.navigate_and_inspect(url) -> dict`, `.close_browser()`, `.reset()` (test-only).
- Produces: `burpsuite_alternative_scan(target, scan_type="comprehensive", headless=True, max_depth=3, max_pages=50) -> dict`, registered as `"burpsuite_alternative_scan"` at `/api/tools/burpsuite-alternative`, category `"webtest"`.

**Legacy (`d689933:hexstrike_server.py:14224-14318`):**
```python
target = params.get("target", "")
scan_type = params.get("scan_type", "comprehensive")
headless = params.get("headless", True)
max_depth = params.get("max_depth", 3)
max_pages = params.get("max_pages", 50)

if not target: 400  # dropped per established precedent - target becomes required, no default

results = {
    'target': target, 'scan_type': scan_type,
    'timestamp': datetime.now().isoformat(), 'success': True
}

if scan_type in ['comprehensive', 'spider']:
    if not browser_agent.driver:
        browser_agent.setup_browser(headless)  # return value ignored in legacy
    browser_result = browser_agent.navigate_and_inspect(target)
    results['browser_analysis'] = browser_result

if scan_type in ['comprehensive', 'spider']:
    spider_result = http_framework.spider_website(target, max_depth, max_pages)
    results['spider_analysis'] = spider_result

if scan_type in ['comprehensive', 'active']:
    discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
    vuln_results = []
    for url in discovered_urls[:20]:
        test_result = http_framework.intercept_request(url)
        if test_result.get('success'):
            vuln_results.append(test_result)
    results['vulnerability_analysis'] = {
        'tested_urls': len(vuln_results),
        'total_vulnerabilities': len(http_framework.vulnerabilities),
        'recent_vulnerabilities': http_framework._get_recent_vulns(20)
    }

total_vulns = len(http_framework.vulnerabilities)
vuln_summary = {}
for vuln in http_framework.vulnerabilities:
    severity = vuln.get('severity', 'unknown')
    vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

results['summary'] = {
    'total_vulnerabilities': total_vulns,
    'vulnerability_breakdown': vuln_summary,
    'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
    'security_score': max(0, 100 - (total_vulns * 5))
}

return jsonify(results)
```

- [ ] **Step 1: Write the failing tests**

Create `tests/test_webtest_tools.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_webtest_tools.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hexstrike.tools.webtest'`.

- [ ] **Step 3: Write minimal implementation**

Read `hexstrike/tools/__init__.py` first to see its current import line before editing it.

Create `hexstrike/tools/webtest.py`:

```python
from typing import Dict, Any
from datetime import datetime
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.http_framework import _http_framework
from hexstrike.tools.browser import _browser_agent


@ToolRegistry.register(
    name="burpsuite_alternative_scan",
    category="webtest",
    description="Comprehensive web application security scan combining browser recon, HTTP spidering, and vulnerability analysis",
    endpoint="/api/tools/burpsuite-alternative"
)
def burpsuite_alternative_scan(target: str, scan_type: str = "comprehensive", headless: bool = True, max_depth: int = 3, max_pages: int = 50) -> Dict[str, Any]:
    try:
        results: Dict[str, Any] = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }

        browser_opened_by_this_scan = False

        if scan_type in ['comprehensive', 'spider']:
            if not _browser_agent.driver:
                setup_success = _browser_agent.setup_browser(headless)
                if setup_success:
                    browser_opened_by_this_scan = True
                    results['browser_analysis'] = _browser_agent.navigate_and_inspect(target)
                else:
                    results['browser_analysis'] = {'success': False, 'error': 'Failed to setup browser'}
            else:
                results['browser_analysis'] = _browser_agent.navigate_and_inspect(target)

        if scan_type in ['comprehensive', 'spider']:
            spider_result = _http_framework.spider_website(target, max_depth, max_pages)
            results['spider_analysis'] = spider_result

        if scan_type in ['comprehensive', 'active']:
            discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
            vuln_results = []
            for url in discovered_urls[:20]:
                test_result = _http_framework.intercept_request(url)
                if test_result.get('success'):
                    vuln_results.append(test_result)
            results['vulnerability_analysis'] = {
                'tested_urls': len(vuln_results),
                'total_vulnerabilities': len(_http_framework.vulnerabilities),
                'recent_vulnerabilities': _http_framework._get_recent_vulns(20)
            }

        total_vulns = len(_http_framework.vulnerabilities)
        vuln_summary: Dict[str, int] = {}
        for vuln in _http_framework.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'vulnerability_breakdown': vuln_summary,
            'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
            'security_score': max(0, 100 - (total_vulns * 5))
        }

        if browser_opened_by_this_scan:
            _browser_agent.close_browser()

        return results

    except Exception as e:
        return {'success': False, 'error': str(e)}
```

Update `hexstrike/tools/__init__.py` to add `webtest` to the existing import line.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_webtest_tools.py -v`
Expected: PASS

- [ ] **Step 5: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add hexstrike/tools/webtest.py hexstrike/tools/__init__.py tests/test_webtest_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port burpsuite_alternative_scan orchestrator tool

Combines browser recon, HTTP spidering, and vulnerability analysis
via the existing http_framework/browser_agent singletons. Two
deliberate, user-approved corrections to legacy: (1) closes the
browser at scan end, but only if this scan itself opened it -
preserving a caller's pre-existing session if one was already open;
(2) checks setup_browser's return value instead of silently falling
through to navigate_and_inspect's own lazy-retry with a hardcoded
default headless setting.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 2: Full verification

**Files:** none created/modified beyond one test addition.

- [ ] **Step 1: Assert `webtest` category has exactly 12 tools**

Add to `tests/test_webtest_tools.py`:

```python
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
```

- [ ] **Step 2: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 3: Sanity-check the MCP layer picks up the new tool**

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
    assert 'burpsuite_alternative_scan' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_webtest_tools.py
git commit -m "$(cat <<'EOF'
test(tools): verify webtest category reaches full 12-tool parity

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```
