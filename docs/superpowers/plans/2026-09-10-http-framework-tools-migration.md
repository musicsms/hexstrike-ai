# HTTP Framework Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `HTTPTestingFramework` (legacy `d689933:hexstrike_server.py:13281-13623`) into a new `hexstrike/tools/http_framework.py`, registering its 7 actions as 7 independent tools under a new `webtest` category: `http_framework_request`, `http_framework_spider`, `http_framework_proxy_history`, `http_framework_set_rules`, `http_framework_set_scope`, `http_framework_repeater`, `http_framework_intruder`.

**Architecture:** `HTTPTestingFramework` is ported as a class holding a persistent `requests.Session`, an accumulating `proxy_history`/`vulnerabilities` list, configurable match/replace rules, and scope restriction — state that persists across separate tool calls within one process, unlike every other tool in this project. A single module-level singleton `_http_framework = HTTPTestingFramework()` is created at import time (mirroring legacy's global instance). Each of the 7 tool functions is a thin `@ToolRegistry.register`-decorated wrapper calling one method on that singleton. A `reset()` method (not present in legacy) is added purely for test isolation, since the singleton would otherwise persist state across unrelated test cases in the same pytest session.

**Tech Stack:** Python 3.13, pytest, `requests` (already a dependency, not yet used anywhere in the modular codebase — this is its first use).

**Spec:** `docs/superpowers/specs/2026-09-10-webtest-tools-design.md` (Group D design, approved). Source-of-truth for original class/tool behavior: `git show d689933:hexstrike_server.py`.

## Global Constraints

- **`setup_proxy` is intentionally NOT ported**, correcting an inaccuracy in the design spec's method list. `git show d689933:hexstrike_server.py | grep -n setup_proxy` confirms it's defined once and never called anywhere — not by any of the 7 `http-framework` actions, not by any other method on the class. It's dead code in legacy, not reachable from any endpoint. Porting an unreachable method with no test surface and no caller violates this project's established YAGNI stance; this deviation is called out explicitly here rather than silently ported or silently dropped.
- **New category `webtest`**, not `web` — these are stateful, session-backed tools, distinct in kind from `web`'s stateless CLI wrappers (same reasoning as the `exploitation` category).
- **Vulnerability-detection heuristics are copied verbatim**: exact regex patterns, exact severity labels (`'medium'`/`'high'`, lowercase — note this differs from every other migrated tool's `'MEDIUM'`/`'HIGH'` uppercase convention; legacy's `HTTPTestingFramework._analyze_response_for_vulns` genuinely uses lowercase, and this plan preserves that exactly rather than "fixing" the inconsistency).
- **State persists across calls by design** — `proxy_history`/`vulnerabilities` are meant to accumulate (a real Burp-Suite-like capture), not reset between tool invocations in production use.
- **`reset()` is test-only** — no production tool function calls it; only test fixtures do, to prevent one test's state leaking into another via the shared module-level singleton.
- **No shell strings, no subprocess** — this class only makes HTTP calls via `requests.Session` and does in-process Python logic (regex, BeautifulSoup parsing); `run_tool_command`/`ProcessManager` are not used anywhere in this file.
- **Legacy manual validation is not reproduced**: `url` (for `request`/`spider`/`intruder` actions) and `host` (for `set_scope`) become required parameters with no default; a missing value raises `TypeError` → 400 via `hexstrike/api/app.py`, per the established precedent throughout this project.
- **Parameter names match legacy's JSON keys exactly**, even where mildly unusual: `http_framework_repeater`'s `request` parameter and `http_framework_intruder`'s `params` parameter are named for legacy's own request-body field names, not renamed for Python style.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: Module skeleton — `HTTPTestingFramework.__init__`/`reset()`, singleton, `set_scope`/`set_match_replace_rules`

**Files:**
- Create: `hexstrike/tools/http_framework.py`
- Modify: `hexstrike/tools/__init__.py` (add `http_framework` to the import line)
- Test: `tests/test_http_framework.py` (create file)

**Interfaces:**
- Produces: `HTTPTestingFramework` class with `__init__`, `reset()`, `set_match_replace_rules(rules: list)`, `set_scope(host: str, include_subdomains: bool = True)`; module-level `_http_framework = HTTPTestingFramework()`; tools `http_framework_set_rules(rules=None)` at `/api/tools/http-framework/set-rules`, `http_framework_set_scope(host, include_subdomains=True)` at `/api/tools/http-framework/set-scope`, both category `"webtest"`.

**Legacy (`d689933:hexstrike_server.py:13285-13296, 13360-13369`):**
```python
def __init__(self):
    self.session = requests.Session()
    self.session.headers.update({'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'})
    self.proxy_history = []
    self.vulnerabilities = []
    self.match_replace_rules = []
    self.scope = None
    self._req_id = 0

def set_match_replace_rules(self, rules: list):
    self.match_replace_rules = rules or []

def set_scope(self, host: str, include_subdomains: bool = True):
    self.scope = {'host': host, 'include_subdomains': include_subdomains}
```

- [ ] **Step 1: Write the failing test**

Read `hexstrike/tools/__init__.py` first to see its current import line before editing it in Step 3.

Create `tests/test_http_framework.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_http_framework.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hexstrike.tools.http_framework'`.

- [ ] **Step 3: Write minimal implementation**

Create `hexstrike/tools/http_framework.py`:

```python
from typing import Dict, Any, Optional, List
import requests
from hexstrike.core.registry import ToolRegistry


class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.match_replace_rules: List[Dict[str, Any]] = []
        self.scope: Optional[Dict[str, Any]] = None
        self._req_id = 0

    def reset(self):
        """Test-only: clear all accumulated state. Never called by production tool functions."""
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []
        self.scope = None
        self._req_id = 0

    def set_match_replace_rules(self, rules: list):
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}


_http_framework = HTTPTestingFramework()


@ToolRegistry.register(
    name="http_framework_set_rules",
    category="webtest",
    description="Configure HTTP request/response match-replace rules",
    endpoint="/api/tools/http-framework/set-rules"
)
def http_framework_set_rules(rules: Optional[list] = None) -> Dict[str, Any]:
    _http_framework.set_match_replace_rules(rules)
    return {"success": True, "rules_set": len(rules or [])}


@ToolRegistry.register(
    name="http_framework_set_scope",
    category="webtest",
    description="Restrict HTTP framework testing to a host scope",
    endpoint="/api/tools/http-framework/set-scope"
)
def http_framework_set_scope(host: str, include_subdomains: bool = True) -> Dict[str, Any]:
    _http_framework.set_scope(host, include_subdomains)
    return {"success": True, "scope": _http_framework.scope}
```

Update `hexstrike/tools/__init__.py` to add `http_framework` to the existing import line.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_http_framework.py -v`
Expected: PASS

- [ ] **Step 5: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add hexstrike/tools/http_framework.py hexstrike/tools/__init__.py tests/test_http_framework.py
git commit -m "$(cat <<'EOF'
feat(tools): create webtest category, port http_framework scope/rules

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 2: `_in_scope` and `_apply_match_replace`

**Files:**
- Modify: `hexstrike/tools/http_framework.py`
- Test: `tests/test_http_framework.py`

**Interfaces:**
- Consumes: `HTTPTestingFramework.scope`, `.match_replace_rules` (Task 1).
- Produces: `HTTPTestingFramework._in_scope(url: str) -> bool`, `_apply_match_replace(url: str, data, headers: dict) -> tuple[str, Any, dict]` — consumed by `intercept_request` in Task 3.

**Legacy (`d689933:hexstrike_server.py:13371-13417`):**
```python
def _in_scope(self, url: str) -> bool:
    if not self.scope:
        return True
    try:
        from urllib.parse import urlparse
        h = urlparse(url).hostname or ''
        target = self.scope.get('host','')
        if not h or not target:
            return True
        if h == target:
            return True
        if self.scope.get('include_subdomains') and h.endswith('.'+target):
            return True
    except Exception:
        return True
    return False

def _apply_match_replace(self, url: str, data, headers: dict):
    import re
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    original_url = url
    out_headers = dict(headers)
    out_data = data
    for rule in self.match_replace_rules:
        where = (rule.get('where') or 'url').lower()
        pattern = rule.get('pattern') or ''
        repl = rule.get('replacement') or ''
        try:
            if where == 'url':
                url = re.sub(pattern, repl, url)
            elif where == 'query':
                pr = urlparse(url)
                qs = parse_qsl(pr.query, keep_blank_values=True)
                new_qs = []
                for k, v in qs:
                    nk = re.sub(pattern, repl, k)
                    nv = re.sub(pattern, repl, v)
                    new_qs.append((nk, nv))
                url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
            elif where == 'headers':
                out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
            elif where == 'body':
                if isinstance(out_data, dict):
                    out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                elif isinstance(out_data, str):
                    out_data = re.sub(pattern, repl, out_data)
        except Exception:
            continue
    if not self._in_scope(url):
        return original_url, data, headers
    return url, out_data, out_headers
```

(The `logger.warning(...)` call on the out-of-scope path is dropped — this project has no `logger` wired into `hexstrike.tools` modules; every other migrated tool already omits legacy's logging calls, since they're presentation-only and orthogonal to tool behavior.)

- [ ] **Step 1: Write the failing test**

```python
def test_in_scope_no_scope_set_allows_everything():
    assert _http_framework._in_scope("http://anything.example.org/") is True


def test_in_scope_exact_host_match():
    _http_framework.set_scope("example.com", include_subdomains=False)
    assert _http_framework._in_scope("http://example.com/path") is True
    assert _http_framework._in_scope("http://other.com/path") is False


def test_in_scope_subdomain_match():
    _http_framework.set_scope("example.com", include_subdomains=True)
    assert _http_framework._in_scope("http://api.example.com/path") is True
    _http_framework.set_scope("example.com", include_subdomains=False)
    assert _http_framework._in_scope("http://api.example.com/path") is False


def test_apply_match_replace_url_rule():
    _http_framework.set_match_replace_rules([{"where": "url", "pattern": "http://", "replacement": "https://"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", {}, {})
    assert url == "https://example.com/"


def test_apply_match_replace_query_rule():
    _http_framework.set_match_replace_rules([{"where": "query", "pattern": "old", "replacement": "new"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/?old=old_value", {}, {})
    assert url == "http://example.com/?new=new_value"


def test_apply_match_replace_headers_rule():
    _http_framework.set_match_replace_rules([{"where": "headers", "pattern": "SECRET", "replacement": "REDACTED"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", {}, {"X-SECRET": "value"})
    assert headers == {"X-REDACTED": "value"}


def test_apply_match_replace_body_dict_rule():
    _http_framework.set_match_replace_rules([{"where": "body", "pattern": "foo", "replacement": "bar"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", {"foo": "foo_val"}, {})
    assert data == {"bar": "bar_val"}


def test_apply_match_replace_body_string_rule():
    _http_framework.set_match_replace_rules([{"where": "body", "pattern": "foo", "replacement": "bar"}])
    url, data, headers = _http_framework._apply_match_replace("http://example.com/", "foo=1", {})
    assert data == "bar=1"


def test_apply_match_replace_out_of_scope_reverts_to_original():
    _http_framework.set_scope("allowed.com", include_subdomains=False)
    _http_framework.set_match_replace_rules([{"where": "url", "pattern": "allowed.com", "replacement": "blocked.com"}])
    url, data, headers = _http_framework._apply_match_replace("http://allowed.com/", {"a": 1}, {"h": "v"})
    assert url == "http://allowed.com/"
    assert data == {"a": 1}
    assert headers == {"h": "v"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_http_framework.py -k "in_scope or apply_match_replace" -v`
Expected: FAIL — `AttributeError: 'HTTPTestingFramework' object has no attribute '_in_scope'`.

- [ ] **Step 3: Write minimal implementation**

Add to `hexstrike/tools/http_framework.py` (add `import re` and `from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse` to the top-level imports):

```python
    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            h = urlparse(url).hostname or ''
            target = self.scope.get('host', '')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.' + target):
                return True
        except Exception:
            return True
        return False

    def _apply_match_replace(self, url: str, data, headers: dict):
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        if not self._in_scope(url):
            return original_url, data, headers
        return url, out_data, out_headers
```

(Insert these methods into the `HTTPTestingFramework` class, after `set_scope`.)

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): add http_framework scope/match-replace logic`)

---

### Task 3: `intercept_request`, vulnerability analysis, `http_framework_request` tool

**Files:**
- Modify: `hexstrike/tools/http_framework.py`
- Test: `tests/test_http_framework.py`

**Interfaces:**
- Consumes: `_apply_match_replace` (Task 2).
- Produces: `HTTPTestingFramework.intercept_request(url, method='GET', data=None, headers=None, cookies=None) -> dict`, `._analyze_response_for_vulns(url, response)`, `._get_recent_vulns(limit=10) -> list`; tool `http_framework_request(url, method="GET", data=None, headers=None, cookies=None)` at `/api/tools/http-framework/request`.

**Legacy (`d689933:hexstrike_server.py:13298-13360, 13495-13556`):** see full source in the design spec's referenced class listing. Key behaviors: dispatches to `session.get/post/put/delete/request` by method (all with `timeout=30`), records request/response into `proxy_history` (response content truncated to 10000 chars), then calls `_analyze_response_for_vulns` which checks 5 missing security headers, 4 sensitive-data regexes, and 5 SQL-error substrings — all lowercase `'medium'`/`'high'` severities, appended to `self.vulnerabilities`.

- [ ] **Step 1: Write the failing test**

```python
class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", elapsed_seconds=0.1):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()

        class _Elapsed:
            def total_seconds(_self):
                return elapsed_seconds
        self.elapsed = _Elapsed()

        class _Request:
            def __init__(_self):
                _self.headers = {}
        self.request = _Request()


def test_intercept_request_success_records_history(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="hello world")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    assert tool is not None
    assert tool.category == "webtest"
    assert tool.endpoint == "/api/tools/http-framework/request"

    res = tool.handler(url="http://example.com/")
    assert res["success"] is True
    assert res["response"]["status_code"] == 200
    assert len(_http_framework.proxy_history) == 1
    assert _http_framework.proxy_history[0]["response"]["content"] == "hello world"


def test_intercept_request_flags_missing_security_headers(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={}, text="hello")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/")
    vuln_types = {v["type"] for v in res["vulnerabilities"]}
    assert vuln_types == {"missing_security_header"}
    assert len(res["vulnerabilities"]) == 5
    assert all(v["severity"] == "medium" for v in res["vulnerabilities"])


def test_intercept_request_flags_sensitive_data_disclosure(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text='{"password": "hunter2"}')
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/")
    vuln_types = {v["type"] for v in res["vulnerabilities"]}
    assert "information_disclosure" in vuln_types


def test_intercept_request_flags_sql_error_indicator(monkeypatch):
    fake_response = _FakeResponse(status_code=500, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="You have an error in your SQL syntax error near line 1")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/")
    vuln_types = {v["type"] for v in res["vulnerabilities"]}
    assert "sql_injection_indicator" in vuln_types


def test_intercept_request_post_method_dispatch(monkeypatch):
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        return _FakeResponse(status_code=201, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="created")

    monkeypatch.setattr(_http_framework.session, "post", fake_post)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://example.com/create", method="POST", data={"name": "x"})
    assert res["success"] is True
    assert captured["url"] == "http://example.com/create"
    assert captured["data"] == {"name": "x"}


def test_intercept_request_failure_returns_error(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=None):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_request")
    res = tool.handler(url="http://unreachable.example.com/")
    assert res["success"] is False
    assert "refused" in res["error"]
```

(Add `import requests` at the top of `tests/test_http_framework.py` for the `ConnectionError` reference.)

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add to `hexstrike/tools/http_framework.py` (add `from datetime import datetime` to imports):

```python
    def intercept_request(self, url: str, method: str = 'GET', data: dict = None,
                           headers: dict = None, cookies: dict = None) -> dict:
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)

            if method.upper() == 'GET':
                response = self.session.get(url, params=data, headers=send_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)

            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }

            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }

            self.proxy_history.append({'request': request_data, 'response': response_data})
            self._analyze_response_for_vulns(url, response)

            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _analyze_response_for_vulns(self, url: str, response):
        vulns = []

        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })

        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]

        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]
                })

        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]

        for error in sql_errors:
            if error.lower() in response.text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })

        self.vulnerabilities.extend(vulns)

    def _get_recent_vulns(self, limit: int = 10):
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []
```

Add the tool function:

```python
@ToolRegistry.register(
    name="http_framework_request",
    category="webtest",
    description="Intercept and analyze an HTTP request/response for vulnerabilities",
    endpoint="/api/tools/http-framework/request"
)
def http_framework_request(url: str, method: str = "GET", data: Optional[dict] = None, headers: Optional[dict] = None, cookies: Optional[dict] = None) -> Dict[str, Any]:
    return _http_framework.intercept_request(url, method, data, headers, cookies)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port http_framework_request with vulnerability analysis`)

---

### Task 4: `http_framework_proxy_history` tool

**Files:**
- Modify: `hexstrike/tools/http_framework.py`
- Test: `tests/test_http_framework.py`

**Interfaces:**
- Consumes: `_http_framework.proxy_history`, `.vulnerabilities` (accumulated by Task 3's `intercept_request`).
- Produces: `http_framework_proxy_history()` at `/api/tools/http-framework/proxy-history`, no parameters.

**Legacy (`d689933:hexstrike_server.py:13351-13356`):**
```python
elif action == "proxy_history":
    return jsonify({
        "success": True,
        "history": http_framework.proxy_history[-100:],
        "total_requests": len(http_framework.proxy_history),
        "vulnerabilities": http_framework.vulnerabilities,
    })
```

- [ ] **Step 1: Write the failing test**

```python
def test_http_framework_proxy_history_handler_invocation_empty():
    tool = ToolRegistry.get("http_framework_proxy_history")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/proxy-history"

    res = tool.handler()
    assert res == {"success": True, "history": [], "total_requests": 0, "vulnerabilities": []}


def test_http_framework_proxy_history_handler_invocation_after_requests(monkeypatch):
    fake_response = _FakeResponse(status_code=200, headers={
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
    }, text="ok")
    monkeypatch.setattr(_http_framework.session, "get", lambda url, params=None, headers=None, timeout=None: fake_response)

    request_tool = ToolRegistry.get("http_framework_request")
    request_tool.handler(url="http://example.com/a")
    request_tool.handler(url="http://example.com/b")

    tool = ToolRegistry.get("http_framework_proxy_history")
    res = tool.handler()
    assert res["total_requests"] == 2
    assert len(res["history"]) == 2
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="http_framework_proxy_history",
    category="webtest",
    description="Retrieve captured HTTP proxy history and vulnerabilities",
    endpoint="/api/tools/http-framework/proxy-history"
)
def http_framework_proxy_history() -> Dict[str, Any]:
    return {
        "success": True,
        "history": _http_framework.proxy_history[-100:],
        "total_requests": len(_http_framework.proxy_history),
        "vulnerabilities": _http_framework.vulnerabilities,
    }
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port http_framework_proxy_history`)

---

### Task 5: `send_custom_request`, `http_framework_repeater` tool

**Files:**
- Modify: `hexstrike/tools/http_framework.py`
- Test: `tests/test_http_framework.py`

**Interfaces:**
- Consumes: `intercept_request` (Task 3).
- Produces: `HTTPTestingFramework.send_custom_request(request_spec: dict) -> dict`; tool `http_framework_repeater(request=None)` at `/api/tools/http-framework/repeater`.

**Legacy (`d689933:hexstrike_server.py:13419-13426`):**
```python
def send_custom_request(self, request_spec: dict) -> dict:
    url = request_spec.get('url','')
    method = request_spec.get('method','GET')
    headers = request_spec.get('headers') or {}
    cookies = request_spec.get('cookies') or {}
    data = request_spec.get('data')
    return self.intercept_request(url, method, data, headers, cookies)
```

- [ ] **Step 1: Write the failing test**

```python
def test_http_framework_repeater_handler_invocation(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        return _FakeResponse(status_code=200, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="ok")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_repeater")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/repeater"

    res = tool.handler(request={"url": "http://example.com/repeat", "method": "GET"})
    assert res["success"] is True
    assert captured["url"] == "http://example.com/repeat"


def test_http_framework_repeater_handler_invocation_no_request():
    tool = ToolRegistry.get("http_framework_repeater")
    res = tool.handler()
    assert res["success"] is False
```

(The no-request case sends `url=""` to `intercept_request`, which fails inside `self.session.get("", ...)` with a `requests` exception, caught by `intercept_request`'s own try/except — a real, faithfully-preserved legacy behavior, not a special case this port adds.)

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
    def send_custom_request(self, request_spec: dict) -> dict:
        url = request_spec.get('url', '')
        method = request_spec.get('method', 'GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)
```

```python
@ToolRegistry.register(
    name="http_framework_repeater",
    category="webtest",
    description="Resend a custom HTTP request with explicit fields",
    endpoint="/api/tools/http-framework/repeater"
)
def http_framework_repeater(request: Optional[dict] = None) -> Dict[str, Any]:
    return _http_framework.send_custom_request(request or {})
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port http_framework_repeater`)

---

### Task 6: `intruder_sniper`, `http_framework_intruder` tool

**Files:**
- Modify: `hexstrike/tools/http_framework.py`
- Test: `tests/test_http_framework.py`

**Interfaces:**
- Consumes: `intercept_request` (Task 3).
- Produces: `HTTPTestingFramework.intruder_sniper(url, method='GET', location='query', params=None, payloads=None, base_data=None, max_requests=100) -> dict`; tool `http_framework_intruder(url, method="GET", location="query", params=None, payloads=None, base_data=None, max_requests=100)` at `/api/tools/http-framework/intruder`.

**Legacy (`d689933:hexstrike_server.py:13428-13471`):** iterates each parameter × each payload (Sniper mode), sending one request per combination via `intercept_request`, flagging "interesting" results where the response status/size changed from a baseline request, or the payload was reflected verbatim in the response body.

- [ ] **Step 1: Write the failing test**

```python
def test_http_framework_intruder_handler_invocation_detects_reflection(monkeypatch):
    call_count = {"n": 0}

    def fake_get(url, params=None, headers=None, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # baseline request
            return _FakeResponse(status_code=200, headers={
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
                "Content-Security-Policy": "default-src 'self'",
            }, text="normal page")
        # fuzzed request reflects the payload
        return _FakeResponse(status_code=200, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="reflected: PAYLOAD_MARKER")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_intruder")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/intruder"

    res = tool.handler(url="http://example.com/search", params=["q"], payloads=["PAYLOAD_MARKER"])
    assert res["success"] is True
    assert res["tested"] == 1
    assert len(res["interesting"]) == 1
    assert res["interesting"][0]["reflected"] is True


def test_http_framework_intruder_handler_invocation_no_findings(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=None):
        return _FakeResponse(status_code=200, headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1", "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
        }, text="unchanged page")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_intruder")
    res = tool.handler(url="http://example.com/search", params=["q"], payloads=["harmless"])
    assert res["tested"] == 1
    assert res["interesting"] == []
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
    def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                         params: list = None, payloads: list = None, base_data: dict = None,
                         max_requests: int = 100) -> dict:
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        base_data = base_data or {}
        interesting = []
        total = 0
        baseline = self.intercept_request(url, method, base_data)
        base_status = baseline.get('response', {}).get('status_code') if baseline.get('success') else None
        base_len = baseline.get('response', {}).get('size') if baseline.get('success') else None
        for p in params:
            for pay in payloads:
                if total >= max_requests:
                    break
                m_url = url
                m_data = dict(base_data)
                m_headers = {}
                if location == 'query':
                    pr = urlparse(url)
                    q = dict(parse_qsl(pr.query, keep_blank_values=True))
                    q[p] = pay
                    m_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                elif location == 'body':
                    m_data[p] = pay
                elif location == 'headers':
                    m_headers[p] = pay
                elif location == 'cookie':
                    self.session.cookies.set(p, pay)
                resp = self.intercept_request(m_url, method, m_data, m_headers)
                total += 1
                if not resp.get('success'):
                    continue
                r = resp['response']
                changed = (base_status is not None and r.get('status_code') != base_status) or (base_len is not None and abs(r.get('size', 0) - base_len) > 150)
                reflected = pay in (r.get('content') or '')
                if changed or reflected:
                    interesting.append({
                        'param': p,
                        'payload': pay,
                        'status_code': r.get('status_code'),
                        'size': r.get('size'),
                        'reflected': reflected
                    })
        return {'success': True, 'tested': total, 'interesting': interesting[:50]}
```

```python
@ToolRegistry.register(
    name="http_framework_intruder",
    category="webtest",
    description="Sniper-mode parameter fuzzing across an HTTP endpoint",
    endpoint="/api/tools/http-framework/intruder"
)
def http_framework_intruder(url: str, method: str = "GET", location: str = "query", params: Optional[list] = None, payloads: Optional[list] = None, base_data: Optional[dict] = None, max_requests: int = 100) -> Dict[str, Any]:
    return _http_framework.intruder_sniper(url, method, location, params, payloads, base_data, max_requests)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port http_framework_intruder`)

---

### Task 7: `spider_website`, `http_framework_spider` tool

**Files:**
- Modify: `hexstrike/tools/http_framework.py`
- Test: `tests/test_http_framework.py`

**Interfaces:**
- Produces: `HTTPTestingFramework.spider_website(base_url, max_depth=3, max_pages=100) -> dict`; tool `http_framework_spider(url, max_depth=3, max_pages=100)` at `/api/tools/http-framework/spider`.

**Legacy (`d689933:hexstrike_server.py:13556-13611`):** BFS crawl from `base_url`, same-origin links only, extracts forms with their inputs, bounded by `max_depth`/`max_pages`. Requires `beautifulsoup4` (`from bs4 import BeautifulSoup`) and `from urllib.parse import urljoin, urlparse` — both need adding to `hexstrike/tools/http_framework.py`'s imports (`urlparse` already imported from Task 2; add `urljoin`).

- [ ] **Step 1: Write the failing test**

```python
_SAMPLE_HTML = """
<html><body>
<a href="/page2">Page 2</a>
<a href="https://external.example.org/other">External</a>
<form action="/submit" method="POST">
    <input name="username" type="text" value="">
    <input name="password" type="password" value="">
</form>
</body></html>
"""


def test_http_framework_spider_handler_invocation(monkeypatch):
    def fake_get(url, timeout=None):
        if url == "http://example.com/":
            return _FakeResponse(status_code=200, text=_SAMPLE_HTML)
        return _FakeResponse(status_code=200, text="<html><body>no links</body></html>")

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_spider")
    assert tool is not None
    assert tool.endpoint == "/api/tools/http-framework/spider"

    res = tool.handler(url="http://example.com/", max_depth=1, max_pages=10)
    assert res["success"] is True
    assert "http://example.com/" in res["discovered_urls"]
    assert "http://example.com/page2" in res["discovered_urls"]
    assert not any("external.example.org" in u for u in res["discovered_urls"])
    assert len(res["forms"]) == 1
    assert res["forms"][0]["method"] == "POST"
    assert {i["name"] for i in res["forms"][0]["inputs"]} == {"username", "password"}


def test_http_framework_spider_handler_invocation_respects_max_pages(monkeypatch):
    def fake_get(url, timeout=None):
        return _FakeResponse(status_code=200, text='<html><body><a href="/next">next</a></body></html>')

    monkeypatch.setattr(_http_framework.session, "get", fake_get)

    tool = ToolRegistry.get("http_framework_spider")
    res = tool.handler(url="http://example.com/", max_depth=10, max_pages=1)
    assert res["total_pages"] <= 1
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add `from urllib.parse import urljoin` and `from bs4 import BeautifulSoup` to imports:

```python
    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        try:
            discovered_urls = set()
            forms = []
            to_visit = [(base_url, 0)]
            visited = set()

            while to_visit and len(discovered_urls) < max_pages:
                current_url, depth = to_visit.pop(0)

                if current_url in visited or depth > max_depth:
                    continue

                visited.add(current_url)

                try:
                    response = self.session.get(current_url, timeout=10)
                    if response.status_code == 200:
                        discovered_urls.add(current_url)
                        soup = BeautifulSoup(response.text, 'html.parser')

                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)
                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                if full_url not in visited and depth < max_depth:
                                    to_visit.append((full_url, depth + 1))

                        for form in soup.find_all('form'):
                            form_data = {
                                'url': current_url,
                                'action': urljoin(current_url, form.get('action', '')),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': []
                            }
                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                form_data['inputs'].append({
                                    'name': input_tag.get('name', ''),
                                    'type': input_tag.get('type', 'text'),
                                    'value': input_tag.get('value', '')
                                })
                            forms.append(form_data)

                except Exception:
                    continue

            return {
                'success': True,
                'discovered_urls': list(discovered_urls),
                'forms': forms,
                'total_pages': len(discovered_urls),
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}
```

```python
@ToolRegistry.register(
    name="http_framework_spider",
    category="webtest",
    description="Spider a website to discover endpoints and forms",
    endpoint="/api/tools/http-framework/spider"
)
def http_framework_spider(url: str, max_depth: int = 3, max_pages: int = 100) -> Dict[str, Any]:
    return _http_framework.spider_website(url, max_depth, max_pages)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(tools): port http_framework_spider`)

---

### Task 8: Full verification

**Files:** none created/modified beyond one test addition.

- [ ] **Step 1: Assert `webtest` category has exactly 7 tools**

Add to `tests/test_http_framework.py`:

```python
def test_webtest_category_has_7_tools():
    from hexstrike.core.registry import ToolRegistry
    webtest_tools = ToolRegistry.get_by_category("webtest")
    assert len(webtest_tools) == 7
    names = {t.name for t in webtest_tools}
    assert names == {
        "http_framework_request", "http_framework_spider", "http_framework_proxy_history",
        "http_framework_set_rules", "http_framework_set_scope", "http_framework_repeater",
        "http_framework_intruder",
    }
```

- [ ] **Step 2: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all PASS.

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
    assert 'http_framework_request' in names
    assert 'http_framework_intruder' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_http_framework.py
git commit -m "$(cat <<'EOF'
test(tools): verify webtest category reaches 7-tool parity (http_framework)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```
