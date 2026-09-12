# Failure Recovery System Port Design Spec

- **Author**: Claude Sonnet 5 & User
- **Date**: 2026-09-11
- **Status**: Approved
- **Scope**: Port `IntelligentErrorHandler` / `FailureRecoverySystem` from the legacy monolith into the modular `hexstrike/` package

---

## 1. Overview & Goals

A caller (an MCP-connected agent, observed calling itself "OptimusPrime") sent
`use_recovery: true` in the JSON body of a `POST /api/tools/nmap` call. The
current registry-based `nmap_scan(target, scan_type, ports, timeout,
additional_args)` has no such parameter, so `create_tool_view` raised
`TypeError` and returned HTTP 400 (already fixed separately by making unknown
params non-fatal — see `hexstrike/api/app.py`'s `ignored_params` handling).

`use_recovery` is not a made-up parameter. It is real, historical, intentional
API surface from the legacy monolith (`hexstrike_server.py` at commit
`d689933`): every one of the `nmap`/`gobuster`/`nuclei` Flask routes read
`use_recovery = params.get("use_recovery", True)` (default **on**) and, when
true, ran the command through `execute_command_with_recovery()` — a
retry/backoff/parameter-adjustment/tool-substitution engine driven by
`IntelligentErrorHandler` (error classification) and `FailureRecoverySystem`
(tool alternatives). The current README still advertises this
(`FailureRecoverySystem — Error handling and recovery`,
`GracefulDegradation — Fault-tolerant operation`).

### Overriding a prior architectural decision

`docs/superpowers/specs/2026-09-11-process-lifecycle-and-task-pool-design.md`
(merged immediately before this spec, PR #27) already audited the full
monolith and explicitly placed `FailureRecoverySystem`, `GracefulDegradation`,
and `IntelligentErrorHandler` in bucket **(b) "duplicates what the calling LLM
already does via MCP reasoning"** — not ported, on the reasoning that an
MCP-connected LLM caller already reads a failed tool result and decides
whether to retry, adjust parameters, or try another tool.

This spec **overrides that decision** for one concrete reason surfaced by
real usage: not every caller of this HTTP API is an LLM doing its own
reasoning loop mid-conversation. A direct HTTP/MCP client that fires a single
tool call and returns the raw result to something else (a script, a queued
job, a non-reasoning pipeline stage) has no reasoning loop to fall back on —
for those callers, `use_recovery` genuinely adds capability rather than
duplicating one. The user explicitly requested the full port with this
context in hand. Kept for the audit trail; not re-litigated further here.

### Goals
- Restore `use_recovery` as working, documented API surface, matching the
  legacy response contract (`recovery_info`, `alternative_tool_suggested`,
  `human_escalation` fields) closely enough that an existing legacy-aware
  caller (like OptimusPrime) gets a coherent response.
- Keep the new implementation architecture-appropriate: adjustment/retry
  operates on structured `Dict[str, Any]` kwargs and re-invokes
  `spec.handler(**kwargs)`, never regex-rewrites a command string (the
  legacy `_rebuild_command_with_params` approach, which the legacy code
  itself calls "a simplified implementation").
- Zero changes to any file under `hexstrike/tools/` — this lives entirely in
  a new `hexstrike/core/recovery.py` plus a small integration point in
  `hexstrike/api/app.py`.

### Non-Goals
- `GracefulDegradation`'s actual fallback probes (raw socket port-check,
  bare `curl` directory check, manual security-header check) — deferred.
  `RecoveryAction.GRACEFUL_DEGRADATION` exists in the ported enum for
  fidelity with the legacy strategy tables (it's assigned to one strategy,
  under `TARGET_UNREACHABLE`) but its handler in this port behaves exactly
  like `ABORT_OPERATION` (return the failed result, stop retrying) rather
  than running a substitute check.
- TaskPool/background-execution integration. Recovery retries run
  synchronously inside the HTTP request, same as the legacy blocking
  behavior. A caller enabling `use_recovery` on a slow tool should expect a
  correspondingly longer wait (up to ~3x a single run, bounded by
  `max_attempts`).
- Actually invoking an alternative tool. Legacy never did this either —
  `SWITCH_TO_ALTERNATIVE_TOOL` only ever populated
  `result["alternative_tool_suggested"]` and returned; "this would require
  the calling function to handle tool switching" (legacy comment, verbatim).
  This port preserves that: it's a suggestion field, not an auto-retry with
  a different tool.
- `error_history`/`ErrorContext.system_resources`/`previous_errors` —
  legacy's audit trail bookkeeping (used only for logging/escalation
  context, `psutil`-based resource snapshots). Not load-bearing to the
  retry/classification decision itself; dropped.

---

## 2. New Module: `hexstrike/core/recovery.py`

Ported from legacy `hexstrike_server.py` (`ErrorType`, `RecoveryAction`,
`RecoveryStrategy`, `IntelligentErrorHandler`, `FailureRecoverySystem`,
`execute_command_with_recovery` — legacy lines ~1558-2130, ~4449-4544,
~8664-8850), adapted as described below. No third-party dependency changes.

### 2.1 Enums & dataclasses (ported verbatim)

```python
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

class RecoveryAction(Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"   # handled as ABORT in this port
    ABORT_OPERATION = "abort_operation"

@dataclass
class RecoveryStrategy:
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds, used only for strategy scoring
```

`ErrorContext` is trimmed to what the decision logic actually consumes:
`tool_name`, `target`, `parameters`, `error_type`, `error_message`,
`attempt_count` (drops `timestamp`/`stack_trace`/`system_resources`/
`previous_errors`, none of which affect the recovery decision).

### 2.2 `classify_error(error_message: str) -> ErrorType`

Ported verbatim: the same ~20-pattern regex table (`timeout|timed out...` →
`TIMEOUT`, `permission denied|access denied...` → `PERMISSION_DENIED`, etc.),
checked with `re.search(pattern, error_text, re.IGNORECASE)`, falling back to
`UNKNOWN`. Legacy also special-cased Python exception *types*
(`TimeoutError`, `PermissionError`, `ConnectionError`, `FileNotFoundError`)
before falling through to the regex table — kept, since `spec.handler(...)`
can raise a real Python exception (not every tool goes through
`run_tool_command`; e.g. `intelligence.py`'s pure-Python tools) as well as
return a `run_tool_command`-style `{"success": False, "error": "..."}` dict.

### 2.3 `RECOVERY_STRATEGIES: Dict[ErrorType, List[RecoveryStrategy]]`

Ported verbatim (all 11 error types, all `success_probability`/
`estimated_time`/`max_attempts`/`backoff_multiplier` values unchanged from
legacy) — this is static data, mechanical to copy, and legacy's numbers are
as good a starting point as any new ones we'd invent.

### 2.4 `select_best_strategy(strategies, attempt_count) -> RecoveryStrategy`

Ported verbatim: filter to `attempt_count <= s.max_attempts`; if none viable,
synthesize an `ESCALATE_TO_HUMAN` fallback strategy; otherwise score each
viable strategy as `success_probability * (0.9 ** (attempt_count - 1)) -
estimated_time / 1000.0` and return the highest-scoring one. (Note: this
means, e.g., for `TIMEOUT` at `attempt_count == 1` the highest-scored action
is `RETRY_WITH_REDUCED_SCOPE`, not `RETRY_WITH_BACKOFF` despite being listed
first — this is legacy's actual behavior, not a bug introduced here; unit
tests pin the exact expected action per attempt count.)

### 2.5 `TOOL_ALTERNATIVES: Dict[str, List[str]]`

Ported from legacy's `_initialize_tool_alternatives`, **re-keyed to current
`ToolRegistry` names** (`"nmap"` → `"nmap_scan"`, `"gobuster"` →
`"gobuster_dir"`, `"feroxbuster"` → `"feroxbuster_scan"`, etc.). Looked up via
a small helper:

```python
def get_alternative_tool(tool_name: str, strategy_params: Dict[str, Any]) -> Optional[str]:
    candidates = [t for t in TOOL_ALTERNATIVES.get(tool_name, []) if ToolRegistry.get(t) is not None]
    # legacy's two context filters (require_no_privileges, prefer_faster_tools), ported verbatim
    ...
    return candidates[0] if candidates else None
```

Filtering every candidate through `ToolRegistry.get(t) is not None` means the
list never suggests a tool that isn't actually registered today, and stays
accurate as more categories get migrated — no maintenance needed here when
that happens.

### 2.6 `adjust_params(spec: ToolSpec, error_type: ErrorType, kwargs: Dict) -> Dict`

This is the one piece that is **not** a verbatim port, because legacy's
`_rebuild_command_with_params` operated on a command *string* via regex/
string-append (and is explicitly labeled "a simplified implementation" in
its own docstring — it only ever appends flags, never replaces an existing
one). The new architecture's tools build `cmd: List[str]` from structured
kwargs, so adjustment is a dict merge instead:

```python
TOOL_PARAM_ADJUSTMENTS: Dict[str, Dict[ErrorType, Dict[str, Any]]] = {
    "nmap_scan":         {ErrorType.TIMEOUT: {"extra_flags": "-T2"},
                           ErrorType.RATE_LIMITED: {"extra_flags": "-T1"}},
    "gobuster_dir":      {ErrorType.TIMEOUT: {"threads": 10},
                           ErrorType.RATE_LIMITED: {"threads": 5},
                           ErrorType.RESOURCE_EXHAUSTED: {"threads": 5}},
    "nuclei_scan":       {ErrorType.TIMEOUT: {"extra_flags": "-timeout 30"},
                           ErrorType.RATE_LIMITED: {"extra_flags": "-rl 10"}},
    "feroxbuster_scan":  {ErrorType.TIMEOUT: {"threads": 5},
                           ErrorType.RATE_LIMITED: {"threads": 3}},
    "ffuf_fuzz":         {ErrorType.RATE_LIMITED: {"extra_flags": "-rate 10"}},
}
GENERIC_ADJUSTMENTS: Dict[ErrorType, Dict[str, Any]] = {
    ErrorType.TIMEOUT: {"timeout": lambda cur: (cur or 300) * 2},
    ErrorType.RATE_LIMITED: {"threads": 3},
    ErrorType.RESOURCE_EXHAUSTED: {"threads": 3},
}
```

`adjust_params`:
1. Looks up the tool-specific table, falling back to `GENERIC_ADJUSTMENTS`.
2. For each adjustment key: `"extra_flags"` is special — appended (space
   joined) to `kwargs["additional_args"]` **only if** `"additional_args"` is
   an accepted parameter of `spec.handler` (true for every registered tool
   today, per convention, but checked rather than assumed). Any other key is
   applied **only if** it's already an accepted parameter name of
   `spec.handler` (via `inspect.signature`) — otherwise silently skipped.
3. This guarantees adjustment can never itself introduce a `TypeError`: it
   only ever sets kwargs the target function already declares.

This is a deliberate simplification versus legacy's tool-specific string
keys (`"timing"`, `"concurrency"`, `"rate-limit"`, `"reduce_ports"`, ...) —
those don't correspond 1:1 to any real kwarg name in the new architecture,
and the signature-filtered merge is strictly safer than what legacy did.

### 2.7 `execute_with_recovery(spec: ToolSpec, kwargs: Dict, max_attempts: int = 3) -> Dict[str, Any]`

Ported structure from `execute_command_with_recovery`, adapted to call
`spec.handler(**kwargs)` instead of shelling out a string:

```python
def execute_with_recovery(spec, kwargs, max_attempts=3):
    accepted = set(inspect.signature(spec.handler).parameters)
    current_kwargs = dict(kwargs)
    history = []
    attempt = 0
    last_result = None

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
        strategy = select_best_strategy(RECOVERY_STRATEGIES[error_type], attempt)  # all 11 ErrorType values are keys (2.3)
        history.append({"attempt": attempt, "error": result.get("error"), "recovery_action": strategy.action.value})

        if strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
            delay = min(strategy.parameters.get("initial_delay", 5) * (strategy.backoff_multiplier ** (attempt - 1)), strategy.parameters.get("max_delay", 60))
            time.sleep(delay)
            continue

        if strategy.action in (RecoveryAction.RETRY_WITH_REDUCED_SCOPE, RecoveryAction.ADJUST_PARAMETERS):
            current_kwargs = adjust_params(spec, error_type, current_kwargs)
            continue

        if strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
            alt = get_alternative_tool(spec.name, strategy.parameters)
            if alt:
                result["alternative_tool_suggested"] = alt
            break

        if strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
            result["human_escalation"] = build_escalation(spec.name, error_type, result.get("error"), attempt, strategy.parameters.get("urgency", "medium"))
            break

        # ABORT_OPERATION and GRACEFUL_DEGRADATION (stubbed as abort): stop.
        break

    last_result["recovery_info"] = {
        "attempts_made": attempt,
        "recovery_applied": True,
        "recovery_history": history,
    }
    return last_result
```

`build_escalation` ports legacy's `escalate_to_human` + `_get_human_suggestions`
(both small, verbatim-portable — a dict of `{timestamp, tool, target,
error_type, error_message, urgency, suggested_actions}`, dropping the
`system_resources`/`previous_errors` fields per the non-goals above).

---

## 3. API Integration (`hexstrike/api/app.py`)

Minimal change to the `create_tool_view` closure added in the earlier
`use_recovery` 400-fix:

```python
def tool_view():
    payload = ...  # unchanged: parse JSON body or query params
    use_recovery = bool(payload.pop("use_recovery", False))   # opt-in, default False

    unknown = {k: payload.pop(k) for k in list(payload) if k not in accepted_params}
    if unknown:
        logger.warning(...)

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
        ...  # unchanged
```

`use_recovery` is popped from `payload` **before** the unknown-params
filter, so it's never mistakenly reported in `ignored_params` — it's a
recognized meta-parameter of the API layer, not a tool kwarg.

**Default is `False`** (opt-in), not `True` like legacy: for a
pentest/security-testing tool, silently retrying against a live target
(extra requests, extra brute-force attempts) without the caller explicitly
asking for it is the wrong default, even though it changes legacy's
out-of-the-box behavior. A caller that wants legacy-equivalent behavior
passes `"use_recovery": true` explicitly.

---

## 4. Testing

**Unit (`tests/test_recovery.py`, new):**
- `classify_error` — one assertion per `ErrorType`, using a representative
  error string plus the exception-type shortcuts.
- `select_best_strategy` — pin the exact expected `RecoveryAction` at
  `attempt_count` 1/2/3 for `ErrorType.TIMEOUT` (documented non-obvious
  ordering above) and at least one other error type.
- `adjust_params` — assert it only ever returns keys present in a fake
  handler's signature (never introduces a new invalid kwarg); assert
  `extra_flags` appends rather than replaces existing `additional_args`.
- `get_alternative_tool` — assert it filters out an alternative not present
  in `ToolRegistry` (using the real registry, since `import hexstrike.tools`
  registers everything) and honors the `require_no_privileges` /
  `prefer_faster_tools` context filters.

**Integration (`tests/test_api.py`, additions):**
- `use_recovery=true`, mocked `execute_command` failing once with a
  timeout-shaped error then succeeding — assert final `success: true` and
  `recovery_info.attempts_made == 2`, `time.sleep` monkeypatched to a no-op
  spy so the test stays fast and can assert it was called with the expected
  delay.
- `use_recovery` omitted (or `false`) — assert exactly one call to
  `execute_command`, no `recovery_info` in the response (unchanged from
  current behavior).
- A `PERMISSION_DENIED`-shaped error with `use_recovery=true` — assert the
  loop stops after 1 attempt with `human_escalation` present (no pointless
  retries against an error retrying can't fix).
