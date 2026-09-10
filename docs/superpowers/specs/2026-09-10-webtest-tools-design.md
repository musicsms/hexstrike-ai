# WebTest Tools (Group D) Design Spec

## Context

This is the final group of legacy tools remaining in the hexstrike-ai modular
migration: `http-framework`, `browser-agent`, and `burpsuite-alternative`
(source: `git show d689933:hexstrike_server.py`). All 87 previously-migrated
tools (see `docs/superpowers/plans/*-migration.md`, commits through PR #12)
are pure, stateless functions: one input, one subprocess or HTTP call, one
output, done. These three are categorically different:

- **`HTTPTestingFramework`** (legacy lines 13281-13623, 343 lines): a
  Burp-Suite-like HTTP testing backend with a persistent `requests.Session`,
  an accumulating request/response `proxy_history`, a `vulnerabilities` list
  that grows across calls, configurable match/replace rules, scope
  restriction, a website spider (via BeautifulSoup), and a simple
  "Sniper"-mode parameter fuzzer (`intruder_sniper`).
- **`BrowserAgent`** (legacy lines 13623-14039, 417 lines): a Selenium-driven
  browser automation backend holding a **live WebDriver process that persists
  across separate tool invocations** (`navigate` → `screenshot` → `close` are
  three separate legacy HTTP calls sharing one browser session), performing
  page inspection (forms, links, scripts, local/session storage, console
  errors, network logs) and both passive and lightweight active
  (reflected-XSS) security analysis.
- **`burpsuite-alternative`**: orchestrates both singletons together across
  three phases (browser recon, HTTP spidering, vulnerability analysis) into
  one combined scan report.

Both classes are instantiated once as legacy global singletons
(`http_framework = HTTPTestingFramework()`, `browser_agent = BrowserAgent()`)
and every one of their multi-action endpoints (`action=request/spider/
proxy_history/set_rules/set_scope/repeater/intruder` for http-framework;
`action=navigate/screenshot/close/status` for browser-agent) dispatches
internally to different behavior sharing one URL — a pattern nothing else in
this codebase uses, since every other tool is "one function, one job."

This spec resolves how these three legacy endpoints map onto the existing
`ToolRegistry` / `hexstrike.tools` architecture (established in
`docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`)
without changing that architecture itself — `ToolSpec.handler: Callable` has
no return-shape or statelessness requirement, so no framework changes are
needed, only new modules and a design for where persistent state lives.

## Goals

- Port `HTTPTestingFramework` and `BrowserAgent` faithfully (full method
  set, not a reduced slice), preserving legacy behavior including its
  request/response analysis heuristics and Selenium page-inspection logic.
- Decompose each multi-action legacy endpoint into one registered tool per
  action, consistent with every other tool in this project.
- Establish a test-isolation strategy for the two long-lived, stateful
  singletons so pytest runs remain deterministic (no cross-test state bleed).
- Prove real Selenium wiring works in this environment (`chromium` +
  `chromedriver` are both installed) via at least one non-mocked integration
  test, while keeping all *tool wrapper* tests fast and mocked, matching the
  rest of the project's test style.

## Non-Goals

- No changes to `hexstrike.core.registry.ToolRegistry`, `hexstrike.api.app`,
  or `hexstrike.mcp.server` — all three already treat a handler's return
  value and lifetime opaquely; nothing here requires framework changes.
- No new third-party dependencies: `requests`, `beautifulsoup4`, `selenium`,
  and `webdriver-manager` are already listed in `requirements.txt` from the
  legacy monolith, simply never yet imported by the modular codebase.
- No attempt to preserve legacy's single-URL multi-action dispatch shape —
  superseded by the one-tool-per-action decision below.
- No CDP-based deep cookie-flag inspection, no headless-detection evasion,
  no capability beyond what legacy's `BrowserAgent`/`HTTPTestingFramework`
  already implemented.

## Architecture

### Module placement

Two new modules under `hexstrike/tools/`, each owning its class, a
module-level singleton, and its registered tool functions:

- `hexstrike/tools/http_framework.py`
- `hexstrike/tools/browser.py`

This was chosen over `hexstrike/agents/` (reserved per the original
architecture spec for AI decision-making / attack-graph exploration, not
tool-backing session state) and over `hexstrike/core/` (reserved for generic
infrastructure like `ProcessManager`, which every tool category uses — these
classes are specific to exactly these tools, not shared infrastructure).

A third module, `hexstrike/tools/webtest.py`, holds only
`burpsuite_alternative_scan`, since it needs both singletons and doesn't
belong to either class individually.

`hexstrike/tools/__init__.py`'s import line gains `http_framework, browser,
webtest`.

### New category: `webtest`

All 12 tools below register under `category="webtest"`, not `"web"` — these
are stateful, session-backed tools, categorically different from `web`'s
stateless CLI wrappers, matching the same reasoning that motivated creating
the `exploitation` category rather than folding those 3 tools into `binary`.

### Full tool list

| New tool name | Legacy source | Endpoint |
|---|---|---|
| `http_framework_request` | `http-framework` action=`request` → `intercept_request` | `/api/tools/http-framework/request` |
| `http_framework_spider` | action=`spider` → `spider_website` | `/api/tools/http-framework/spider` |
| `http_framework_proxy_history` | action=`proxy_history` | `/api/tools/http-framework/proxy-history` |
| `http_framework_set_rules` | action=`set_rules` → `set_match_replace_rules` | `/api/tools/http-framework/set-rules` |
| `http_framework_set_scope` | action=`set_scope` → `set_scope` | `/api/tools/http-framework/set-scope` |
| `http_framework_repeater` | action=`repeater` → `send_custom_request` | `/api/tools/http-framework/repeater` |
| `http_framework_intruder` | action=`intruder` → `intruder_sniper` | `/api/tools/http-framework/intruder` |
| `browser_navigate` | `browser-agent` action=`navigate` → `navigate_and_inspect` (+ optional `run_active_tests`) | `/api/tools/browser-agent/navigate` |
| `browser_screenshot` | action=`screenshot` | `/api/tools/browser-agent/screenshot` |
| `browser_close` | action=`close` → `close_browser` | `/api/tools/browser-agent/close` |
| `browser_status` | action=`status` | `/api/tools/browser-agent/status` |
| `burpsuite_alternative_scan` | `burpsuite-alternative` (full endpoint) | `/api/tools/burpsuite-alternative` |

This brings the project total from 87 to 99 tools — exceeding the original
legacy count of 90, since 3 multi-action legacy endpoints expand into 12.

### `HTTPTestingFramework` — ported faithfully

The full method set is ported unchanged in behavior:
`intercept_request`, `setup_proxy`, `set_match_replace_rules`, `set_scope`,
`_in_scope`, `_apply_match_replace`, `send_custom_request`,
`intruder_sniper`, `_analyze_response_for_vulns`, `_get_recent_vulns`,
`spider_website`. The vulnerability-detection heuristics (missing security
headers, sensitive-data regexes, SQL-error-string matching) are copied
verbatim, including their exact regex patterns and severity labels — these
are legacy's actual detection logic, not incidental scaffolding, and
changing them would change what the tool finds.

The module-level singleton (`_http_framework = HTTPTestingFramework()`) is
created at import time, matching legacy's global-instance pattern.

### `BrowserAgent` — ported faithfully

The full method set is ported unchanged in behavior:
`setup_browser`, `navigate_and_inspect`, `_get_console_errors`,
`_analyze_cookies`, `_analyze_security_headers`, `_detect_mixed_content`,
`_extended_passive_analysis`, `run_active_tests`, `_get_local_storage`,
`_get_session_storage`, `_extract_forms`, `_extract_links`,
`_extract_inputs`, `_extract_scripts`, `_get_network_logs`,
`_analyze_page_security`, `close_browser`.

**Exception-handling normalization** (style only, no behavior change):
legacy's several bare `except:` clauses in the extraction/storage helpers
become `except Exception:` — this only changes behavior for
`KeyboardInterrupt`/`SystemExit`, which was never the intent of the bare
catch, consistent with earlier normalizations this session (e.g. `gdb`'s
temp-file cleanup moving from bare `except:` to `except OSError:`).

The module-level singleton (`_browser_agent = BrowserAgent()`) is created at
import time. Chrome options (headless flag, sandbox/GPU/security-testing
flags, proxy server, logging prefs) are ported verbatim from
`setup_browser`. No explicit `Service(executable_path=...)` is set — Selenium
resolves `chromedriver` from `PATH` (confirmed present at
`/usr/bin/chromedriver` in this environment) the same way legacy's bare
`webdriver.Chrome(options=chrome_options)` did. `webdriver-manager` (also
listed in `requirements.txt`, imported but effectively unused by legacy's own
`setup_browser`) is likewise not used here — it exists to auto-download a
matching chromedriver when none is present on `PATH`, which isn't needed in
an environment that already has one installed.

### State lifecycle

Both singletons live for the process's lifetime, same as legacy's globals.
Repeated calls to `http_framework_request` genuinely accumulate into the
same `proxy_history`/`vulnerabilities` — this is the intended Burp-Suite-like
behavior (an accumulating capture), not something to reset between calls in
production use.

**Browser lifecycle, preserved exactly:**
- `browser_navigate`: if `_browser_agent.driver is None`, lazily calls
  `setup_browser()` first (auto-init on first navigate).
- `browser_screenshot`: returns an error ("Browser not initialized. Use
  navigate action first.") if `driver is None` — no lazy init here.
- `browser_close`: no-op if `driver` is already `None` (legacy's
  `if self.driver:` guard prevents calling `.quit()` on nothing).
- `browser_status`: reports `driver is not None`, `len(screenshots)`,
  `len(page_sources)` — never errors.

### Error handling

Each class method keeps its own internal `try/except`, returning
`{"success": False, "error": str(e)}` rather than letting exceptions
propagate to the generic 500 handler in `hexstrike/api/app.py`. This is
legacy's actual behavior (the try/except lives inside `intercept_request`,
`navigate_and_inspect`, `spider_website`, etc., not just at the Flask route
level) — a failed request or a Selenium error surfaces as a normal
`success: False` tool result, consistent with how every other tool in this
project reports failure.

### Test isolation for shared singleton state

Since `_http_framework`/`_browser_agent` persist for the whole pytest
session, tests need a way to avoid one test's state leaking into another
(e.g. `proxy_history` accumulating across unrelated `intercept_request`
tests). Each class gains a small `reset()` method that clears its own
mutable collections (`proxy_history`, `vulnerabilities`,
`match_replace_rules`, `scope` for `HTTPTestingFramework`; `screenshots`,
`page_sources`, `network_logs`, and `driver = None` after `close_browser()`
for `BrowserAgent`) — not a legacy method, but a small testability addition
with no production behavior impact (nothing in the tool functions calls
`reset()`; only test fixtures do). This mirrors `ToolRegistry.clear()`'s
existing role solving the identical class of problem for tool registration
state.

## Testing Plan

- **`tests/test_http_framework.py`**: mocks `requests.Session.get/post/put/
  delete/request` (matching how every other tool test mocks its I/O layer).
  Covers `intercept_request` success/failure paths, vulnerability detection
  (each of the 4 detection categories: missing headers, sensitive-data
  regex, SQL-error strings — at least one positive and one negative case
  each), match/replace rule application across all four `where` targets
  (`url`/`query`/`headers`/`body`), scope in/out-of-scope filtering,
  `spider_website` (mocked `session.get` returning small fixture HTML,
  exercising real `BeautifulSoup` parsing — no real network), and
  `intruder_sniper`'s changed-response and reflected-payload detection.
- **`tests/test_browser_agent.py`**: **one real, non-mocked integration
  test** driving actual `chromium`/`chromedriver` — `setup_browser
  (headless=True)` → `navigate_and_inspect` against a `data:text/html,...`
  URL or small local HTML fixture → assert real page info was extracted →
  `close_browser()`. This proves the real Selenium wiring (Chrome options,
  driver lifecycle, JS execution for storage extraction, DOM queries)
  actually works in this environment, mirroring how `tests/test_process.py`
  runs real subprocess commands rather than mocking `subprocess.run`
  entirely. All *tool wrapper* tests (`browser_navigate`, `browser_screenshot`,
  `browser_close`, `browser_status`) mock the `_browser_agent` singleton's
  methods directly — no browser needed for those.
- **`tests/test_webtest_tools.py`**: `burpsuite_alternative_scan` orchestration
  — mocks both singletons, verifies which phases run for each `scan_type`
  (`comprehensive`/`spider`/`passive`/`active`), and the summary/
  security-score arithmetic.
- Full-suite run (`./.venv/bin/python3 -m pytest tests/ -v`) must stay green
  throughout; MCP sanity check (`mcp.list_tools()`) confirms all 12 new
  tools are exposed, same as every prior migration in this project.

## Rollout

Three PRs, matching this session's established one-unit-of-work-per-PR
cadence, each independently green:

1. `http_framework.py` + its 7 tools + `tests/test_http_framework.py`
2. `browser.py` + its 4 tools + `tests/test_browser_agent.py`
3. `webtest.py`'s `burpsuite_alternative_scan` (needs both singletons from
   PRs 1-2, so branches after both are merged) + `tests/test_webtest_tools.py`
   + full `webtest` category verification (12/12) + MCP sanity check

Each PR gets its own `docs/superpowers/plans/YYYY-MM-DD-*.md` implementation
plan (via the `writing-plans` skill), written against this spec, the same
way every prior migration's plan referenced the original architecture spec.
