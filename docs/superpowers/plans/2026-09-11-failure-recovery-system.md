# Failure Recovery System (`use_recovery`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the legacy monolith's `use_recovery` API parameter as working, opt-in, automatic retry/backoff/parameter-adjustment behavior for any registered tool, without touching any file under `hexstrike/tools/`.

**Architecture:** A new standalone module `hexstrike/core/recovery.py` ports the legacy `IntelligentErrorHandler`/`FailureRecoverySystem` (error classification via regex, a per-error-type strategy table, parameter adjustment, tool-alternative suggestion, human escalation) as pure functions operating on `ToolSpec` + a kwargs `Dict`, re-invoking `spec.handler(**kwargs)` instead of legacy's regex command-string rewriting. `hexstrike/api/app.py`'s `create_tool_view` gets one new branch: when the caller sends `use_recovery: true`, the call goes through `execute_with_recovery()` instead of a single direct `spec.handler(**payload)` call.

**Tech Stack:** Python 3.13, pytest, Flask (`hexstrike.api.app.create_app`), stdlib only (`re`, `time`, `inspect`, `dataclasses`, `enum`) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-11-failure-recovery-system-design.md`

## Global Constraints

- `use_recovery` defaults to **`False`** (opt-in) — this is a deliberate deviation from the legacy default of `True`, for pentest-safety reasons documented in the spec §3. Never make it default-on.
- Zero changes to any file under `hexstrike/tools/`. All new logic lives in `hexstrike/core/recovery.py` plus the integration point in `hexstrike/api/app.py`.
- No `shell=True`, no command-string rewriting. Parameter adjustment always operates on a `Dict[str, Any]` of kwargs, filtered through `inspect.signature(spec.handler).parameters` before being applied, so an adjustment can never itself introduce a `TypeError`.
- `RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL` only ever populates `result["alternative_tool_suggested"]` and stops — it must never actually invoke the alternative tool (matches legacy behavior exactly).
- `RecoveryAction.GRACEFUL_DEGRADATION` is handled identically to `RecoveryAction.ABORT_OPERATION` in this port (stop, return the failed result) — no fallback-probe logic (socket port-check, bare curl, etc.) is implemented. This is an explicit non-goal, not an oversight.
- Retry loops run synchronously inside the HTTP request (blocking), matching legacy behavior. No TaskPool integration.
- Every commit message ends with:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
  ```
- Every task must leave `python -m pytest tests/ -q --ignore=tests/test_mcp.py` fully green (that one ignored file fails to collect for an unrelated, pre-existing reason — a missing `fastmcp` module — and `test_browser_agent.py::test_navigate_and_inspect_real_browser_end_to_end` is a known pre-existing failure unrelated to this work; no task in this plan should introduce any *new* failure).

---

### Task 1: Error classification (`ErrorType`, `classify_error`)

**Files:**
- Create: `hexstrike/core/recovery.py`
- Test: `tests/test_recovery.py` (create)

**Interfaces:**
- Consumes: nothing (foundational).
- Produces: `ErrorType` (Enum, 11 members), `classify_error(error_message: str, exception: Optional[Exception] = None) -> ErrorType`. Later tasks import both from `hexstrike.core.recovery`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_recovery.py`:

```python
import pytest
from hexstrike.core.recovery import ErrorType, classify_error


def test_classify_error_timeout():
    assert classify_error("Connection timeout after 30s") == ErrorType.TIMEOUT
    assert classify_error("operation timed out") == ErrorType.TIMEOUT


def test_classify_error_permission_denied():
    assert classify_error("Permission denied") == ErrorType.PERMISSION_DENIED
    assert classify_error("sudo required to run this scan") == ErrorType.PERMISSION_DENIED


def test_classify_error_network_unreachable():
    assert classify_error("Network unreachable") == ErrorType.NETWORK_UNREACHABLE
    assert classify_error("Connection refused") == ErrorType.NETWORK_UNREACHABLE


def test_classify_error_rate_limited():
    assert classify_error("429 Too Many Requests") == ErrorType.RATE_LIMITED
    assert classify_error("quota exceeded") == ErrorType.RATE_LIMITED


def test_classify_error_tool_not_found():
    assert classify_error("bash: nmap: command not found") == ErrorType.TOOL_NOT_FOUND
    assert classify_error("executable not found") == ErrorType.TOOL_NOT_FOUND


def test_classify_error_invalid_parameters():
    assert classify_error("nmap: invalid option -- 'z'") == ErrorType.INVALID_PARAMETERS
    assert classify_error("syntax error near unexpected token") == ErrorType.INVALID_PARAMETERS


def test_classify_error_resource_exhausted():
    assert classify_error("out of memory") == ErrorType.RESOURCE_EXHAUSTED
    assert classify_error("too many open files") == ErrorType.RESOURCE_EXHAUSTED


def test_classify_error_authentication_failed():
    assert classify_error("authentication failed") == ErrorType.AUTHENTICATION_FAILED
    assert classify_error("expired token") == ErrorType.AUTHENTICATION_FAILED


def test_classify_error_target_unreachable():
    assert classify_error("target not responding") == ErrorType.TARGET_UNREACHABLE
    assert classify_error("dns resolution failed") == ErrorType.TARGET_UNREACHABLE


def test_classify_error_parsing_error():
    assert classify_error("json decode error") == ErrorType.PARSING_ERROR
    assert classify_error("malformed response") == ErrorType.PARSING_ERROR


def test_classify_error_unknown_fallback():
    assert classify_error("") == ErrorType.UNKNOWN
    assert classify_error("something completely unrecognizable happened") == ErrorType.UNKNOWN


def test_classify_error_exception_type_shortcuts():
    assert classify_error("", TimeoutError()) == ErrorType.TIMEOUT
    assert classify_error("", PermissionError()) == ErrorType.PERMISSION_DENIED
    assert classify_error("", ConnectionError()) == ErrorType.NETWORK_UNREACHABLE
    assert classify_error("", FileNotFoundError()) == ErrorType.TOOL_NOT_FOUND
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike.core.recovery'`

- [ ] **Step 3: Write minimal implementation**

Create `hexstrike/core/recovery.py`:

```python
import re
import time
import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from hexstrike.core.registry import ToolRegistry, ToolSpec


class ErrorType(Enum):
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"


_ERROR_PATTERNS: Dict[str, ErrorType] = {
    r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
    r"operation timed out|command timeout": ErrorType.TIMEOUT,

    r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
    r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,

    r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
    r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,

    r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
    r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,

    r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
    r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,

    r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
    r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,

    r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
    r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,

    r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
    r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,

    r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
    r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,

    r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
    r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR,
}


def classify_error(error_message: str, exception: Optional[Exception] = None) -> ErrorType:
    if exception is not None:
        if isinstance(exception, TimeoutError):
            return ErrorType.TIMEOUT
        if isinstance(exception, PermissionError):
            return ErrorType.PERMISSION_DENIED
        if isinstance(exception, ConnectionError):
            return ErrorType.NETWORK_UNREACHABLE
        if isinstance(exception, FileNotFoundError):
            return ErrorType.TOOL_NOT_FOUND

    text = (error_message or "").lower()
    for pattern, error_type in _ERROR_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            return error_type
    return ErrorType.UNKNOWN
```

(The `time`, `inspect`, `dataclass`, `ToolRegistry`, `ToolSpec` imports are unused until later tasks in this plan — they're included now so later tasks only append code, never re-edit the import block.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: PASS (12 tests)

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/recovery.py tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): port error classification from legacy FailureRecoverySystem

First piece of the use_recovery port (see
docs/superpowers/specs/2026-09-11-failure-recovery-system-design.md):
regex-based error-message classification into ErrorType, ported
verbatim from the legacy monolith's IntelligentErrorHandler.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

### Task 2: Recovery strategy table and selection (`RecoveryAction`, `RecoveryStrategy`, `RECOVERY_STRATEGIES`, `select_best_strategy`)

**Files:**
- Modify: `hexstrike/core/recovery.py` (append)
- Test: `tests/test_recovery.py` (append)

**Interfaces:**
- Consumes: `ErrorType` from Task 1.
- Produces: `RecoveryAction` (Enum, 7 members), `RecoveryStrategy` (dataclass: `action`, `parameters: Dict[str, Any]`, `max_attempts: int`, `backoff_multiplier: float`, `success_probability: float`, `estimated_time: int`), `RECOVERY_STRATEGIES: Dict[ErrorType, List[RecoveryStrategy]]` (all 11 `ErrorType` values as keys), `select_best_strategy(strategies: List[RecoveryStrategy], attempt_count: int) -> RecoveryStrategy`. Task 6 calls `select_best_strategy(RECOVERY_STRATEGIES[error_type], attempt)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_recovery.py`:

```python
from hexstrike.core.recovery import RecoveryAction, RECOVERY_STRATEGIES, select_best_strategy


def test_recovery_strategies_cover_every_error_type():
    assert set(RECOVERY_STRATEGIES.keys()) == set(ErrorType)


def test_select_best_strategy_timeout_progression():
    strategies = RECOVERY_STRATEGIES[ErrorType.TIMEOUT]
    assert select_best_strategy(strategies, 1).action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE
    assert select_best_strategy(strategies, 2).action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE
    assert select_best_strategy(strategies, 3).action == RecoveryAction.RETRY_WITH_BACKOFF


def test_select_best_strategy_permission_denied_escalates_immediately():
    strategies = RECOVERY_STRATEGIES[ErrorType.PERMISSION_DENIED]
    assert select_best_strategy(strategies, 1).action == RecoveryAction.ESCALATE_TO_HUMAN


def test_select_best_strategy_falls_back_to_escalation_when_all_exhausted():
    strategies = RECOVERY_STRATEGIES[ErrorType.TIMEOUT]
    # attempt_count 4 exceeds every strategy's max_attempts (3, 2, 1)
    result = select_best_strategy(strategies, 4)
    assert result.action == RecoveryAction.ESCALATE_TO_HUMAN
    assert result.max_attempts == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: FAIL with `ImportError: cannot import name 'RecoveryAction' from 'hexstrike.core.recovery'`

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/core/recovery.py`:

```python
class RecoveryAction(Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"


@dataclass
class RecoveryStrategy:
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds, used only for strategy scoring


RECOVERY_STRATEGIES: Dict[ErrorType, List[RecoveryStrategy]] = {
    ErrorType.TIMEOUT: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 5, "max_delay": 60}, 3, 2.0, 0.7, 30),
        RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, {"reduce_threads": True, "reduce_timeout": True}, 2, 1.0, 0.8, 45),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"prefer_faster_tools": True}, 1, 1.0, 0.6, 60),
    ],
    ErrorType.PERMISSION_DENIED: [
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Privilege escalation required", "urgency": "medium"}, 1, 1.0, 0.9, 300),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"require_no_privileges": True}, 1, 1.0, 0.5, 30),
    ],
    ErrorType.NETWORK_UNREACHABLE: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 10, "max_delay": 120}, 3, 2.0, 0.6, 60),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"prefer_offline_tools": True}, 1, 1.0, 0.4, 30),
    ],
    ErrorType.RATE_LIMITED: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 30, "max_delay": 300}, 5, 1.5, 0.9, 180),
        RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"reduce_rate": True, "increase_delays": True}, 2, 1.0, 0.8, 120),
    ],
    ErrorType.TOOL_NOT_FOUND: [
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"find_equivalent": True}, 1, 1.0, 0.7, 15),
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Tool installation required", "urgency": "low"}, 1, 1.0, 0.9, 600),
    ],
    ErrorType.INVALID_PARAMETERS: [
        RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"use_defaults": True, "remove_invalid": True}, 3, 1.0, 0.8, 10),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"simpler_interface": True}, 1, 1.0, 0.6, 30),
    ],
    ErrorType.RESOURCE_EXHAUSTED: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, {"reduce_memory": True, "reduce_threads": True}, 2, 1.0, 0.7, 60),
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 60, "max_delay": 300}, 2, 2.0, 0.5, 180),
    ],
    ErrorType.AUTHENTICATION_FAILED: [
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Authentication credentials required", "urgency": "high"}, 1, 1.0, 0.9, 300),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"no_auth_required": True}, 1, 1.0, 0.4, 30),
    ],
    ErrorType.TARGET_UNREACHABLE: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 15, "max_delay": 180}, 3, 2.0, 0.6, 90),
        RecoveryStrategy(RecoveryAction.GRACEFUL_DEGRADATION, {"skip_target": True, "continue_with_others": True}, 1, 1.0, 1.0, 5),
    ],
    ErrorType.PARSING_ERROR: [
        RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"change_output_format": True, "add_parsing_flags": True}, 2, 1.0, 0.7, 20),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"better_output_format": True}, 1, 1.0, 0.6, 30),
    ],
    ErrorType.UNKNOWN: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 5, "max_delay": 30}, 2, 2.0, 0.3, 45),
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Unknown error encountered", "urgency": "medium"}, 1, 1.0, 0.9, 300),
    ],
}


def select_best_strategy(strategies: List[RecoveryStrategy], attempt_count: int) -> RecoveryStrategy:
    viable = [s for s in strategies if attempt_count <= s.max_attempts]
    if not viable:
        return RecoveryStrategy(
            action=RecoveryAction.ESCALATE_TO_HUMAN,
            parameters={"message": "All recovery strategies exhausted", "urgency": "high"},
            max_attempts=1,
            backoff_multiplier=1.0,
            success_probability=0.9,
            estimated_time=300,
        )

    scored = []
    for strategy in viable:
        adjusted_probability = strategy.success_probability * (0.9 ** (attempt_count - 1))
        score = adjusted_probability - (strategy.estimated_time / 1000.0)
        scored.append((score, strategy))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return scored[0][1]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: PASS (16 tests)

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/recovery.py tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): port recovery strategy table and selection logic

Ports RecoveryAction/RecoveryStrategy and the full 11-error-type
RECOVERY_STRATEGIES table plus select_best_strategy's scoring
algorithm verbatim from the legacy IntelligentErrorHandler.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

### Task 3: Alternative-tool suggestion (`TOOL_ALTERNATIVES`, `get_alternative_tool`)

**Files:**
- Modify: `hexstrike/core/recovery.py` (append)
- Test: `tests/test_recovery.py` (append)

**Interfaces:**
- Consumes: `ToolRegistry` (already imported in Task 1's header).
- Produces: `TOOL_ALTERNATIVES: Dict[str, List[str]]`, `get_alternative_tool(tool_name: str, strategy_params: Dict[str, Any]) -> Optional[str]`. Task 6 calls `get_alternative_tool(spec.name, strategy.parameters)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_recovery.py`:

```python
import hexstrike.core.recovery as recovery_module
from hexstrike.core.recovery import get_alternative_tool


def test_get_alternative_tool_returns_none_when_no_alternatives_listed(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {})
    assert get_alternative_tool("totally_unknown_tool", {}) is None


def test_get_alternative_tool_filters_to_registered_tools_only(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {"tool_a": ["tool_b", "tool_c", "tool_d"]})
    monkeypatch.setattr(
        recovery_module.ToolRegistry, "get",
        staticmethod(lambda name: object() if name in ("tool_c", "tool_d") else None),
    )
    # tool_b isn't "registered" per the stub above, so it's skipped entirely
    assert get_alternative_tool("tool_a", {}) == "tool_c"


def test_get_alternative_tool_context_filter_falls_back_when_all_excluded(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {"tool_a": ["nmap_scan", "masscan_scan"]})
    monkeypatch.setattr(recovery_module.ToolRegistry, "get", staticmethod(lambda name: object()))
    # Both candidates are in the require_no_privileges denylist, so the filter
    # excludes everything and (matching legacy behavior) falls back to the
    # unfiltered candidate list rather than returning None.
    assert get_alternative_tool("tool_a", {"require_no_privileges": True}) == "nmap_scan"


def test_get_alternative_tool_context_filter_excludes_when_alternative_remains(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {"tool_a": ["nmap_scan", "rustscan_scan"]})
    monkeypatch.setattr(recovery_module.ToolRegistry, "get", staticmethod(lambda name: object()))
    assert get_alternative_tool("tool_a", {"require_no_privileges": True}) == "rustscan_scan"


def test_tool_alternatives_nmap_scan_entry_uses_current_registry_names():
    assert "rustscan_scan" in recovery_module.TOOL_ALTERNATIVES["nmap_scan"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: FAIL with `ImportError: cannot import name 'get_alternative_tool' from 'hexstrike.core.recovery'`

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/core/recovery.py`:

```python
TOOL_ALTERNATIVES: Dict[str, List[str]] = {
    "nmap_scan": ["rustscan_scan", "masscan_scan", "zmap"],
    "rustscan_scan": ["nmap_scan", "masscan_scan"],
    "masscan_scan": ["nmap_scan", "rustscan_scan", "zmap"],

    "gobuster_dir": ["feroxbuster_scan", "dirsearch_scan", "ffuf_fuzz", "dirb_scan"],
    "feroxbuster_scan": ["gobuster_dir", "dirsearch_scan", "ffuf_fuzz"],
    "dirsearch_scan": ["gobuster_dir", "feroxbuster_scan", "ffuf_fuzz"],
    "ffuf_fuzz": ["gobuster_dir", "feroxbuster_scan", "dirsearch_scan"],

    "nuclei_scan": ["jaeles_scan", "nikto_scan", "w3af"],
    "jaeles_scan": ["nuclei_scan", "nikto_scan"],
    "nikto_scan": ["nuclei_scan", "jaeles_scan", "w3af"],

    "katana_crawl": ["gau_discover", "waybackurls_discover", "hakrawler_crawl"],
    "gau_discover": ["katana_crawl", "waybackurls_discover", "hakrawler_crawl"],
    "waybackurls_discover": ["gau_discover", "katana_crawl", "hakrawler_crawl"],

    "arjun_scan": ["paramspider_mine", "x8_scan", "ffuf_fuzz"],
    "paramspider_mine": ["arjun_scan", "x8_scan"],
    "x8_scan": ["arjun_scan", "paramspider_mine"],

    "sqlmap_scan": ["sqlninja", "jsql-injection"],
    "dalfox_scan": ["xsser_scan", "xsstrike"],

    "subfinder": ["amass_enum", "assetfinder", "findomain"],
    "amass_enum": ["subfinder", "assetfinder", "findomain"],
    "assetfinder": ["subfinder", "amass_enum", "findomain"],

    "prowler_scan": ["scout_suite_scan", "cloudmapper_run"],
    "scout_suite_scan": ["prowler_scan", "cloudmapper_run"],

    "trivy_scan": ["clair_scan", "docker_bench_security_scan"],
    "clair_scan": ["trivy_scan", "docker_bench_security_scan"],

    "ghidra_analyze": ["radare2_analyze", "ida", "binary-ninja"],
    "radare2_analyze": ["ghidra_analyze", "objdump_scan", "gdb_analyze"],
    "gdb_analyze": ["radare2_analyze", "lldb"],

    "pwntools_exploit": ["ropper_scan", "ropgadget"],
    "ropper_scan": ["ropgadget", "pwntools_exploit"],
}


def get_alternative_tool(tool_name: str, strategy_params: Dict[str, Any]) -> Optional[str]:
    candidates = [t for t in TOOL_ALTERNATIVES.get(tool_name, []) if ToolRegistry.get(t) is not None]
    if not candidates:
        return None

    filtered = []
    for alt in candidates:
        if strategy_params.get("require_no_privileges") and alt in ("nmap_scan", "masscan_scan"):
            continue
        if strategy_params.get("prefer_faster_tools") and alt in ("amass_enum", "w3af"):
            continue
        filtered.append(alt)

    if not filtered:
        filtered = candidates
    return filtered[0]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: PASS (21 tests)

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/recovery.py tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): port alternative-tool suggestion, re-keyed to registry names

TOOL_ALTERNATIVES ports legacy's tool-substitution map, re-keyed from
legacy's short names (e.g. "nmap") to current ToolRegistry names (e.g.
"nmap_scan"). get_alternative_tool filters every candidate through
ToolRegistry.get() so it never suggests an unregistered tool, staying
accurate as more categories get migrated. Matches legacy: this only
ever suggests, never auto-invokes, the alternative.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

### Task 4: Parameter adjustment (`TOOL_PARAM_ADJUSTMENTS`, `GENERIC_ADJUSTMENTS`, `adjust_params`)

**Files:**
- Modify: `hexstrike/core/recovery.py` (append)
- Test: `tests/test_recovery.py` (append)

**Interfaces:**
- Consumes: `ErrorType` from Task 1; `ToolSpec` (already imported in Task 1's header).
- Produces: `adjust_params(spec: ToolSpec, error_type: ErrorType, kwargs: Dict[str, Any]) -> Dict[str, Any]`. Task 6 calls `adjust_params(spec, error_type, current_kwargs)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_recovery.py`:

```python
from hexstrike.core.recovery import adjust_params


def _fake_spec(name, handler):
    return ToolSpec(name=name, category="test", description="", endpoint="/x", handler=handler)


def test_adjust_params_applies_tool_specific_override():
    def handler(target, threads=10, additional_args=None):
        return {"success": True}
    spec = _fake_spec("gobuster_dir", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "threads": 10})
    assert result["threads"] == 10  # gobuster_dir's TIMEOUT override sets threads to 10


def test_adjust_params_skips_keys_not_in_handler_signature():
    def handler(target, additional_args=None):  # no "threads" param
        return {"success": True}
    spec = _fake_spec("gobuster_dir", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x"})
    assert "threads" not in result


def test_adjust_params_extra_flags_appends_to_existing_additional_args():
    def handler(target, additional_args=None):
        return {"success": True}
    spec = _fake_spec("nmap_scan", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "additional_args": "-Pn"})
    assert result["additional_args"] == "-Pn -T2"


def test_adjust_params_extra_flags_sets_when_absent():
    def handler(target, additional_args=None):
        return {"success": True}
    spec = _fake_spec("nmap_scan", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x"})
    assert result["additional_args"] == "-T2"


def test_adjust_params_falls_back_to_generic_for_unlisted_tool():
    def handler(target, threads=10, additional_args=None):
        return {"success": True}
    spec = _fake_spec("some_future_tool", handler)

    result = adjust_params(spec, ErrorType.RATE_LIMITED, {"target": "x", "threads": 10})
    assert result["threads"] == 3  # GENERIC_ADJUSTMENTS[RATE_LIMITED]


def test_adjust_params_generic_timeout_doubles_current_value():
    def handler(target, timeout=300, additional_args=None):
        return {"success": True}
    spec = _fake_spec("some_future_tool", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "timeout": 100})
    assert result["timeout"] == 200


def test_adjust_params_does_not_mutate_input_dict():
    def handler(target, threads=10, additional_args=None):
        return {"success": True}
    spec = _fake_spec("gobuster_dir", handler)

    original = {"target": "x", "threads": 99}
    adjust_params(spec, ErrorType.TIMEOUT, original)
    assert original["threads"] == 99
```

Add the `ToolSpec` import at the top of `tests/test_recovery.py` (alongside the existing `hexstrike.core.recovery` imports):

```python
from hexstrike.core.registry import ToolSpec
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: FAIL with `ImportError: cannot import name 'adjust_params' from 'hexstrike.core.recovery'`

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/core/recovery.py`:

```python
TOOL_PARAM_ADJUSTMENTS: Dict[str, Dict[ErrorType, Dict[str, Any]]] = {
    "nmap_scan": {
        ErrorType.TIMEOUT: {"extra_flags": "-T2"},
        ErrorType.RATE_LIMITED: {"extra_flags": "-T1"},
    },
    "gobuster_dir": {
        ErrorType.TIMEOUT: {"threads": 10},
        ErrorType.RATE_LIMITED: {"threads": 5},
        ErrorType.RESOURCE_EXHAUSTED: {"threads": 5},
    },
    "nuclei_scan": {
        ErrorType.TIMEOUT: {"extra_flags": "-timeout 30"},
        ErrorType.RATE_LIMITED: {"extra_flags": "-rl 10"},
    },
    "feroxbuster_scan": {
        ErrorType.TIMEOUT: {"threads": 5},
        ErrorType.RATE_LIMITED: {"threads": 3},
    },
    "ffuf_fuzz": {
        ErrorType.RATE_LIMITED: {"extra_flags": "-rate 10"},
    },
}

GENERIC_ADJUSTMENTS: Dict[ErrorType, Dict[str, Any]] = {
    ErrorType.TIMEOUT: {"timeout": lambda current: (current or 300) * 2},
    ErrorType.RATE_LIMITED: {"threads": 3},
    ErrorType.RESOURCE_EXHAUSTED: {"threads": 3},
}


def adjust_params(spec: ToolSpec, error_type: ErrorType, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    accepted = set(inspect.signature(spec.handler).parameters)
    adjustments = TOOL_PARAM_ADJUSTMENTS.get(spec.name, {}).get(error_type)
    if adjustments is None:
        adjustments = GENERIC_ADJUSTMENTS.get(error_type, {})

    adjusted = dict(kwargs)
    for key, value in adjustments.items():
        if key == "extra_flags":
            if "additional_args" not in accepted:
                continue
            existing = adjusted.get("additional_args") or ""
            adjusted["additional_args"] = f"{existing} {value}".strip()
            continue
        if key in accepted:
            adjusted[key] = value(adjusted.get(key)) if callable(value) else value
    return adjusted
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: PASS (28 tests)

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/recovery.py tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): add signature-safe parameter adjustment

adjust_params replaces legacy's regex command-string rewriting
(_rebuild_command_with_params, self-documented in the monolith as "a
simplified implementation") with a kwargs-dict merge filtered through
the target handler's real inspect.signature. An adjustment can never
introduce a TypeError: any key the handler doesn't declare is silently
skipped rather than applied.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

### Task 5: Human escalation (`build_escalation`)

**Files:**
- Modify: `hexstrike/core/recovery.py` (append)
- Test: `tests/test_recovery.py` (append)

**Interfaces:**
- Consumes: `ErrorType` from Task 1.
- Produces: `build_escalation(tool_name: str, target: str, error_type: ErrorType, error_message: str, attempt_count: int, urgency: str = "medium") -> Dict[str, Any]`, returning `{"tool", "target", "error_type", "error_message", "attempt_count", "urgency", "suggested_actions"}`. Task 6 calls `build_escalation(spec.name, current_kwargs.get("target", "unknown"), error_type, result.get("error"), attempt, strategy.parameters.get("urgency", "medium"))`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_recovery.py`:

```python
from hexstrike.core.recovery import build_escalation


def test_build_escalation_shape():
    escalation = build_escalation("nmap_scan", "10.0.0.1", ErrorType.PERMISSION_DENIED, "permission denied", 2, "high")
    assert escalation["tool"] == "nmap_scan"
    assert escalation["target"] == "10.0.0.1"
    assert escalation["error_type"] == "permission_denied"
    assert escalation["error_message"] == "permission denied"
    assert escalation["attempt_count"] == 2
    assert escalation["urgency"] == "high"
    assert escalation["suggested_actions"] == [
        "Run the command with sudo privileges",
        "Check file/directory permissions",
        "Verify user is in required groups",
    ]


def test_build_escalation_tool_not_found_suggestion_names_the_tool():
    escalation = build_escalation("katana_crawl", "x.com", ErrorType.TOOL_NOT_FOUND, "not found", 1, "low")
    assert escalation["suggested_actions"][0] == "Install katana_crawl using package manager"


def test_build_escalation_default_suggestion_for_unmapped_error_type():
    escalation = build_escalation("nmap_scan", "x", ErrorType.PARSING_ERROR, "malformed", 1)
    assert escalation["urgency"] == "medium"  # default param
    assert escalation["suggested_actions"] == ["Review error details and logs"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_escalation' from 'hexstrike.core.recovery'`

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/core/recovery.py`:

```python
def _human_suggestions(tool_name: str, error_type: ErrorType) -> List[str]:
    if error_type == ErrorType.PERMISSION_DENIED:
        return [
            "Run the command with sudo privileges",
            "Check file/directory permissions",
            "Verify user is in required groups",
        ]
    if error_type == ErrorType.TOOL_NOT_FOUND:
        return [
            f"Install {tool_name} using package manager",
            "Check if tool is in PATH",
            "Verify tool installation",
        ]
    if error_type == ErrorType.NETWORK_UNREACHABLE:
        return [
            "Check network connectivity",
            "Verify target is accessible",
            "Check firewall rules",
        ]
    if error_type == ErrorType.RATE_LIMITED:
        return [
            "Wait before retrying",
            "Use slower scan rates",
            "Check API rate limits",
        ]
    return ["Review error details and logs"]


def build_escalation(
    tool_name: str,
    target: str,
    error_type: ErrorType,
    error_message: str,
    attempt_count: int,
    urgency: str = "medium",
) -> Dict[str, Any]:
    return {
        "tool": tool_name,
        "target": target,
        "error_type": error_type.value,
        "error_message": error_message,
        "attempt_count": attempt_count,
        "urgency": urgency,
        "suggested_actions": _human_suggestions(tool_name, error_type),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: PASS (31 tests)

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/recovery.py tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): port human-escalation payload builder

build_escalation ports legacy's escalate_to_human + _get_human_suggestions,
dropping the system_resources/previous_errors fields (audit-trail
bookkeeping not load-bearing to the recovery decision — see spec
non-goals).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

### Task 6: Retry loop orchestration (`execute_with_recovery`)

**Files:**
- Modify: `hexstrike/core/recovery.py` (append)
- Test: `tests/test_recovery.py` (append)

**Interfaces:**
- Consumes: everything from Tasks 1-5 (`classify_error`, `RECOVERY_STRATEGIES`, `select_best_strategy`, `adjust_params`, `get_alternative_tool`, `build_escalation`) plus `ToolSpec`.
- Produces: `execute_with_recovery(spec: ToolSpec, kwargs: Dict[str, Any], max_attempts: int = 3) -> Dict[str, Any]`. Task 7 calls `execute_with_recovery(spec, payload)` from `hexstrike/api/app.py`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_recovery.py`:

```python
from hexstrike.core.recovery import execute_with_recovery


def test_execute_with_recovery_backoff_then_succeeds(monkeypatch):
    sleeps = []
    monkeypatch.setattr(recovery_module.time, "sleep", lambda seconds: sleeps.append(seconds))

    calls = {"count": 0}

    def handler(target):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"success": False, "error": "rate limit exceeded"}
        return {"success": True, "output": "ok"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})

    assert result["success"] is True
    assert calls["count"] == 2
    assert result["recovery_info"]["attempts_made"] == 2
    assert result["recovery_info"]["recovery_applied"] is True
    assert len(result["recovery_info"]["recovery_history"]) == 1
    assert result["recovery_info"]["recovery_history"][0]["recovery_action"] == "retry_with_backoff"
    assert sleeps == [30]  # RATE_LIMITED initial_delay, attempt 1: 30 * 1.5**0


def test_execute_with_recovery_adjusts_params_then_succeeds():
    seen_timeouts = []

    def handler(target, timeout=300):
        seen_timeouts.append(timeout)
        if len(seen_timeouts) == 1:
            return {"success": False, "error": "operation timed out"}
        return {"success": True, "output": "ok"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x", "timeout": 300})

    assert result["success"] is True
    assert seen_timeouts == [300, 600]  # GENERIC_ADJUSTMENTS[TIMEOUT] doubles it
    assert result["recovery_info"]["attempts_made"] == 2
    assert result["recovery_info"]["recovery_history"][0]["recovery_action"] == "retry_with_reduced_scope"


def test_execute_with_recovery_escalates_and_stops_after_one_attempt():
    calls = {"count": 0}

    def handler(target):
        calls["count"] += 1
        return {"success": False, "error": "permission denied"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})

    assert result["success"] is False
    assert calls["count"] == 1
    assert result["recovery_info"]["attempts_made"] == 1
    assert result["human_escalation"]["tool"] == "some_tool"
    assert result["human_escalation"]["target"] == "x"
    assert result["human_escalation"]["error_type"] == "permission_denied"


def test_execute_with_recovery_handles_raised_exception():
    def handler(target):
        raise FileNotFoundError("nmap: command not found")

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})

    # TOOL_NOT_FOUND's best strategy at attempt 1 is SWITCH_TO_ALTERNATIVE_TOOL;
    # no alternative is registered for "some_tool" so it just stops.
    assert result["success"] is False
    assert result["recovery_info"]["attempts_made"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: FAIL with `ImportError: cannot import name 'execute_with_recovery' from 'hexstrike.core.recovery'`

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/core/recovery.py`:

```python
def execute_with_recovery(spec: ToolSpec, kwargs: Dict[str, Any], max_attempts: int = 3) -> Dict[str, Any]:
    current_kwargs = dict(kwargs)
    history: List[Dict[str, Any]] = []
    attempt = 0
    last_result: Dict[str, Any] = {"success": False, "error": "recovery loop did not execute"}

    while attempt < max_attempts:
        attempt += 1
        try:
            result = spec.handler(**current_kwargs)
        except Exception as exc:
            result = {"success": False, "error": str(exc)}
        last_result = result

        if result.get("success"):
            result["recovery_info"] = {
                "attempts_made": attempt,
                "recovery_applied": len(history) > 0,
                "recovery_history": history,
            }
            return result

        error_type = classify_error(result.get("error") or "")
        strategy = select_best_strategy(RECOVERY_STRATEGIES[error_type], attempt)
        history.append({
            "attempt": attempt,
            "error": result.get("error"),
            "recovery_action": strategy.action.value,
        })

        if strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
            delay = min(
                strategy.parameters.get("initial_delay", 5) * (strategy.backoff_multiplier ** (attempt - 1)),
                strategy.parameters.get("max_delay", 60),
            )
            time.sleep(delay)
            continue

        if strategy.action in (RecoveryAction.RETRY_WITH_REDUCED_SCOPE, RecoveryAction.ADJUST_PARAMETERS):
            current_kwargs = adjust_params(spec, error_type, current_kwargs)
            continue

        if strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
            alt = get_alternative_tool(spec.name, strategy.parameters)
            if alt:
                last_result["alternative_tool_suggested"] = alt
            break

        if strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
            last_result["human_escalation"] = build_escalation(
                spec.name,
                current_kwargs.get("target", "unknown"),
                error_type,
                result.get("error"),
                attempt,
                strategy.parameters.get("urgency", "medium"),
            )
            break

        # ABORT_OPERATION, and GRACEFUL_DEGRADATION (stubbed as abort in this
        # port — see spec non-goals): stop, fall through to the return below.
        break

    last_result["recovery_info"] = {
        "attempts_made": attempt,
        "recovery_applied": True,
        "recovery_history": history,
    }
    return last_result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_recovery.py -v`
Expected: PASS (35 tests)

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/recovery.py tests/test_recovery.py
git commit -m "$(cat <<'EOF'
feat(recovery): add execute_with_recovery retry-loop orchestration

Wires classify_error -> select_best_strategy -> (backoff sleep /
adjust_params-and-retry / suggest-alternative-and-stop /
escalate-and-stop / abort) into the retry loop, capped at max_attempts
(default 3, matching legacy). Ports execute_command_with_recovery's
structure but calls spec.handler(**kwargs) instead of shelling out a
rewritten command string.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

### Task 7: Wire `use_recovery` into the API layer

**Files:**
- Modify: `hexstrike/api/app.py`
- Test: `tests/test_api.py` (append)

**Interfaces:**
- Consumes: `execute_with_recovery` from Task 6.
- Produces: `POST`/`GET /api/tools/<name>` now accepts an opt-in `use_recovery` field (JSON body or query string), default `False`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_api.py`:

```python
def test_tool_execution_route_use_recovery_retries_then_succeeds(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    import hexstrike.core.recovery as recovery_module
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(recovery_module.time, "sleep", lambda seconds: None)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"success": False, "command": " ".join(cmd), "output": "", "error": "rate limit exceeded", "cached": False}
        return {"success": True, "command": " ".join(cmd), "output": "ok", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1", "use_recovery": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["recovery_info"]["attempts_made"] == 2
    assert calls["count"] == 2


def test_tool_execution_route_use_recovery_defaults_to_false(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        return {"success": True, "command": " ".join(cmd), "output": "ok", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "recovery_info" not in data
    assert calls["count"] == 1


def test_tool_execution_route_use_recovery_escalates_on_permission_denied(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        return {"success": False, "command": " ".join(cmd), "output": "", "error": "permission denied", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1", "use_recovery": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is False
    assert data["recovery_info"]["attempts_made"] == 1
    assert "human_escalation" in data
    assert calls["count"] == 1


def test_tool_execution_route_get_method_use_recovery_string_false_is_falsy(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        return {"success": False, "command": " ".join(cmd), "output": "", "error": "permission denied", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.get("/api/tools/nmap?target=127.0.0.1&use_recovery=false")
    assert res.status_code == 200
    data = res.get_json()
    assert "recovery_info" not in data
    assert calls["count"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api.py -v`
Expected: FAIL — `test_tool_execution_route_use_recovery_retries_then_succeeds` and the escalation test fail because `use_recovery` isn't recognized yet (the tool runs once, unmodified, so `recovery_info`/`human_escalation` are never in the response and `calls["count"]` stays at 1).

- [ ] **Step 3: Write minimal implementation**

Edit `hexstrike/api/app.py`:

```python
import inspect
import logging
from flask import Flask, request, jsonify
from hexstrike.core.registry import ToolRegistry, ToolSpec
from hexstrike.core.logging_config import configure_logging
from hexstrike.core.recovery import execute_with_recovery
from hexstrike.api.routes import api_bp
import hexstrike.tools  # Ensure all tools are imported and registered

logger = logging.getLogger(__name__)

def create_tool_view(spec: ToolSpec):
    accepted_params = set(inspect.signature(spec.handler).parameters)

    def tool_view():
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
        else:
            payload = request.args.to_dict()

        use_recovery_raw = payload.pop("use_recovery", False)
        if isinstance(use_recovery_raw, str):
            use_recovery = use_recovery_raw.strip().lower() in ("1", "true", "yes", "on")
        else:
            use_recovery = bool(use_recovery_raw)

        # Callers (older/legacy MCP clients, agents guessing at parameters
        # like "use_recovery" from the pre-refactor monolith's FailureRecoverySystem)
        # sometimes send fields this tool doesn't accept. Drop them instead of
        # a hard 400 so the actual scan still runs.
        unknown = {k: payload.pop(k) for k in list(payload) if k not in accepted_params}
        if unknown:
            logger.warning("Ignoring unsupported params for %s: %s", spec.name, sorted(unknown))

        try:
            if use_recovery:
                result = execute_with_recovery(spec, payload)
            else:
                result = spec.handler(**payload)
            if unknown:
                result = dict(result)
                result["ignored_params"] = sorted(unknown)
            return jsonify(result)
        except TypeError as err:
            return jsonify({
                "success": False,
                "error": f"Invalid arguments for {spec.name}: {str(err)}",
                "command": spec.name
            }), 400
        except Exception as err:
            return jsonify({
                "success": False,
                "error": str(err),
                "command": spec.name
            }), 500
    tool_view.__name__ = f"view_{spec.name}"
    return tool_view

def create_app(debug: bool = False) -> Flask:
    configure_logging()
    app = Flask("hexstrike")
    app.debug = debug

    # Register system endpoints
    app.register_blueprint(api_bp)

    # Mount dynamic tool routes
    for spec in ToolRegistry.get_all_tools():
        app.add_url_rule(
            rule=spec.endpoint,
            endpoint=f"tool_{spec.name}",
            view_func=create_tool_view(spec),
            methods=["GET", "POST"]
        )

    return app
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_api.py -v`
Expected: PASS (all tests in the file, including the 4 new ones)

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest tests/ -q --ignore=tests/test_mcp.py`
Expected: all pass except the one pre-existing, unrelated `test_navigate_and_inspect_real_browser_end_to_end` failure (see Global Constraints).

- [ ] **Step 6: Commit**

```bash
git add hexstrike/api/app.py tests/test_api.py
git commit -m "$(cat <<'EOF'
feat(api): wire opt-in use_recovery into tool execution routes

POST/GET /api/tools/<name> now accepts use_recovery (default False,
a deliberate deviation from the legacy monolith's default-True — see
spec §3 for the pentest-safety reasoning). When true, the call runs
through hexstrike/core/recovery.py's execute_with_recovery instead of
a single direct handler call, restoring the legacy FailureRecoverySystem
response contract (recovery_info, alternative_tool_suggested,
human_escalation) for callers that rely on it, such as the MCP agent
that originally surfaced this as a 400 error before the earlier
unknown-params fix made it non-fatal.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VFjZSRJm926vDGsR6UdUS4
EOF
)"
```

---

## Post-plan verification

After Task 7's commit, run the full suite one more time as a sanity check:

```bash
python -m pytest tests/ -q --ignore=tests/test_mcp.py
```

Expected: same pass count as before this plan started, plus every test added across Tasks 1-7 (35 in `tests/test_recovery.py`, 4 new in `tests/test_api.py`), and no new failures beyond the one pre-existing, documented one.
