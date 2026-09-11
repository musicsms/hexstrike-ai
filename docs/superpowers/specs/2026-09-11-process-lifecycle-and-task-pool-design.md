# Process Lifecycle Registry + Task Pool (Phase 3 of Intelligence-Layer Port) Design Spec

## Context

This is Phase 3 of a staged port of the legacy monolith's (`hexstrike_server.py`,
17,289 lines, pre-migration) "intelligence layer" — the part of the original
codebase that was never carried over during the 90→99 tool `ToolRegistry`
migration (PRs #1-16). Phase 1 (PR #25) ported `TechnologyDetector` and
`RateLimitDetector`. Phase 2 (PR #26) ported the three real `CVEIntelligenceManager`
methods. This phase, and a full audit of every remaining class in the monolith
(see below), covers the last pieces worth porting.

**The audit.** Every class in the monolith not yet ported was read and
classified into one of four buckets:

- **(a) Real infrastructure, worth porting** — deterministic, no LLM-reasoning
  overlap, and (critically) actually used by real tool execution in the
  monolith, not just exposed through a standalone demo/admin API.
- **(b) Duplicates what the calling LLM already does via MCP reasoning** —
  tool selection scoring, canned exploit-payload templates, static attack-plan
  generation, heuristic error-recovery suggestions. ~5,700 lines across
  `IntelligentDecisionEngine`, `BugBountyWorkflowManager`, the four-class CTF
  cluster, `VulnerabilityCorrelator`, `AIExploitGenerator` + 8 exploit
  subclasses, `AIPayloadGenerator`, `ParameterOptimizer`, `FailureRecoverySystem`,
  `GracefulDegradation`, `IntelligentErrorHandler`. All confirmed via grep to be
  used by 0-3 call sites in the entire monolith (standalone demo routes), never
  by the actual tool wrappers (nmap_scan, gobuster_dir, etc.). Not ported.
- **(c) Dead code** — `PythonEnvironmentManager` (zero call sites anywhere).
  Not ported.
- **(d) Already has an equivalent** — `HexStrikeCache` (superseded by
  `ProcessManager`'s existing cache), `ColoredFormatter` (cosmetic log
  coloring; `hexstrike/core/logging_config.py` from Phase 2 already has
  functional logging), `PerformanceMonitor` (superseded by this spec's
  `ResourceMonitor`). Not ported.

**What's actually in bucket (a), and this spec's scope:**

The monolith has *two* differently-named process managers that must not be
confused:

1. `EnhancedProcessManager` / `ProcessPool` / `AdvancedCache` /
   `PerformanceDashboard` (legacy lines 4877-5560) — an auto-scaling worker-pool
   with `execute_command_async()`/`get_task_result()`. Confirmed via grep: its
   singleton `enhanced_process_manager` is called **only** from 17 standalone
   `/api/process/*` admin routes. No security tool (nmap, gobuster, ...) ever
   calls it. It also runs `subprocess.Popen(command, shell=True)` — accepting
   an arbitrary shell string — a real injection-surface downgrade from this
   project's existing list-argv, no-`shell=True` execution.
2. `ProcessManager` (legacy lines 5576-5688, distinct class, same name as
   today's `hexstrike/core/process.py:ProcessManager`) — "Enhanced process
   manager for command termination and monitoring." Confirmed via grep: this
   one **is** called by `EnhancedCommandExecutor`, which is what the legacy
   `execute_command()` — the function every single legacy tool wrapper calls
   to run its subprocess — uses internally. Every tool run got registered here
   (PID, command, start time), and this class exposed list/status/terminate
   (SIGTERM→SIGKILL)/pause/resume (SIGSTOP/SIGCONT). This capability was
   silently dropped when `hexstrike/core/process.py`'s `ProcessManager` was
   written for the modular package — the modular version kept only the cache,
   not the registry/kill/pause/monitor behavior.

This spec ports **#2's capability** (process registry, kill, pause/resume),
**not #1** (no async submit/poll of arbitrary shell strings, no auto-scaling,
no `shell=True`). It also folds in two small, genuinely-used, previously
un-audited pieces:

- `ResourceMonitor` (legacy lines 5423-5501, part of the (1) cluster but
  independently useful) — CPU/memory/disk/network snapshots via `psutil`
  (already a dependency).
- `TelemetryCollector` (legacy lines 6736-6782) — global command counters
  (executed/succeeded/failed, avg execution time, uptime). Confirmed used by
  every legacy tool execution via `EnhancedCommandExecutor`. ~46 lines, cheap,
  no equivalent exists today.

Combining registry+kill/pause with a *safe* version of "run something in the
background and check on it later" (renamed `TaskPool`, not `ProcessPool`) is a
deliberate design choice, not a re-inclusion of bucket (1): a task pool that
only ever dispatches to already-registered `ToolRegistry` tools (never a raw
shell string) needs the process registry anyway to let a caller terminate a
task that's still running — "kill task X" has to resolve to "find and signal
the OS subprocess(es) task X spawned," which requires exactly the registry
this spec is restoring for other reasons. Building them separately would mean
building the PID-to-owner correlation twice.

## Goals

- Restore the process registry/list/terminate/pause/resume capability that
  every legacy tool execution had and every current tool execution lacks.
- Let an MCP/HTTP caller submit a registered tool call that runs in the
  background (returns a `task_id` immediately) and poll for its result later,
  without blocking the calling request for the tool's full runtime.
- Let a caller terminate a still-running background task, which must actually
  kill the OS subprocess it spawned (not just abandon a Python thread).
- Restore system resource visibility (`ResourceMonitor`) and aggregate
  execution telemetry (`TelemetryCollector`), both cheap and independently
  useful for an operator or LLM agent gauging system load before deciding to
  parallelize more work.
- Preserve `hexstrike/core/process.py:ProcessManager.execute_command()`'s
  existing behavior (caching, timeout, stdin, cwd) exactly — it is the single
  most-used, most-tested function in the codebase (93% coverage, all 105
  tools depend on it either directly or via `run_tool_command`).

## Non-Goals

- No arbitrary shell-string execution API (`execute_command_async(command: str)`
  from the legacy `EnhancedProcessManager`). `TaskPool.submit` only accepts a
  `tool_name` already present in `ToolRegistry` plus its keyword params —
  exactly the same dispatch `create_tool_view`/`mcp/server.py` already do
  synchronously.
- No auto-scaling worker pool. `TaskPool` wraps a fixed-size
  `concurrent.futures.ThreadPoolExecutor`; pool size is a config constant. The
  legacy auto-scaling thresholds (`cpu_high: 85.0`, etc.) were never validated
  even in the original and add real testing difficulty (timing-dependent
  behavior) for uncertain benefit at single-server scale.
- No porting of `FileOperationsManager` (legacy lines 8928-9023, ~95 lines,
  small `/tmp/hexstrike_files` CRUD utility) or bucket (b)/(c)/(d) classes
  listed above — explicitly out of scope, deferred/skipped per the audit.
- No changes to `ToolRegistry`, `ToolSpec`, or the MCP/Flask dispatch layers
  beyond what's needed to register the new `process` category tools the same
  way every other category already registers.
- No cross-process or persistent (disk/DB) task state. Task and process
  registries are in-memory, scoped to one running server process — consistent
  with every existing singleton in `hexstrike/core` (`default_process_manager`,
  `ToolRegistry`'s class-level dict).

## Architecture

```
LLM/HTTP caller
      |
      v
task_submit(tool_name, params)  -->  TaskPool.submit()
      |                                    |
      | returns task_id immediately        | looks up ToolRegistry.get(tool_name)
      v                                    | submits spec.handler(**params) to
task_status(task_id)  -->  TaskPool.get_status()   ThreadPoolExecutor(max_workers=N)
task_terminate(task_id) -> TaskPool.terminate()          |
      |                                                  v
      | on terminate: find PID(s) tagged        spec.handler runs in worker thread
      | with this task_id via the registry            |
      v                                                  v
process_list() / process_status(pid) --> ProcessManager.active_processes registry
process_terminate(pid) / pause(pid) / resume(pid)         |
                                                            v
                                          ProcessManager.execute_command()
                                          (Popen, registers PID + current
                                           thread-local task_id before
                                           communicate(), deregisters after)
```

### Component 1: `hexstrike/core/process.py` (extend `ProcessManager`, in place)

**New state**, added to `__init__`:
- `self.active_processes: Dict[int, Dict[str, Any]] = {}` — pid → `{pid, command, start_time, status, task_id, process}` (`process` is the live `Popen` object, needed to signal it later).
- `self._registry_lock = threading.RLock()`.
- `self.telemetry = {"commands_executed": 0, "successful_commands": 0, "failed_commands": 0, "total_execution_time": 0.0, "start_time": time.time()}`.
- Module-level `_current_task_id = threading.local()` (not per-instance — thread-local state belongs at module scope, mirroring how it would be set from any thread regardless of which `ProcessManager` instance is used; in practice only `default_process_manager` exists).

**`execute_command()` internals change** from:
```python
res = subprocess.run(command, stdout=PIPE, stderr=PIPE, text=True, timeout=timeout, ...)
```
to:
```python
popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if cwd is not None:
    popen_kwargs["cwd"] = cwd
proc = subprocess.Popen(command, **popen_kwargs)
with self._registry_lock:
    self.active_processes[proc.pid] = {
        "pid": proc.pid, "command": cmd_str, "start_time": start_time,
        "status": "running", "task_id": getattr(_current_task_id, "value", None),
        "process": proc,
    }
try:
    stdout, stderr = proc.communicate(input=stdin_input, timeout=timeout)
    returncode = proc.returncode
except subprocess.TimeoutExpired:
    proc.kill()
    proc.communicate()
    raise  # existing TimeoutExpired handling below is unchanged
finally:
    with self._registry_lock:
        self.active_processes.pop(proc.pid, None)
```
The public return shape, cache behavior, and `TimeoutExpired`/generic-exception
handling paths are **unchanged** — this is an internal swap of `subprocess.run`
for `subprocess.Popen` + `communicate`, not a behavior change. This is the
highest-risk part of this spec (see Testing Plan).

**New methods:**
- `list_active_processes() -> List[Dict[str, Any]]` — snapshot of the registry (excluding the raw `process` object; includes `running_time = time.time() - start_time`).
- `get_process_status(pid: int) -> Optional[Dict[str, Any]]`.
- `terminate_process(pid: int, timeout: int = 10) -> Dict[str, Any]` — `SIGTERM`, wait up to `timeout`s, `SIGKILL` if still alive. Returns `{"success": bool, "pid": pid, "method": "graceful"|"forced"|"not_found"}`.
- `pause_process(pid: int) -> Dict[str, Any]` / `resume_process(pid: int) -> Dict[str, Any]` — `SIGSTOP`/`SIGCONT` via `os.kill`. On `os.name == "nt"`, returns `{"success": False, "error": "pause/resume is not supported on Windows"}` without attempting the signal.
- `record_telemetry(success: bool, execution_time: float)` — called at the end of every `execute_command()` path (cache hit, success, failure, timeout all count as "executed"; cache hits are recorded as instant successes, matching legacy behavior of `HexStrikeCache` short-circuiting before `EnhancedCommandExecutor` telemetry).
- `get_telemetry_stats() -> Dict[str, Any]` — `uptime_seconds`, `commands_executed`, `success_rate`, `average_execution_time`, plus `system_metrics: default_resource_monitor.get_current_usage()` (reuses Component 2 instead of calling `psutil` a second time).

### Component 2: `hexstrike/core/resource_monitor.py` (new)

```python
class ResourceMonitor:
    def __init__(self, history_size: int = 100): ...
    def get_current_usage(self) -> Dict[str, Any]: ...   # cpu/memory/disk/network snapshot via psutil; appends to history
    def get_usage_trends(self) -> Dict[str, Any]: ...     # rolling avg over last min(10, len(history)) recorded snapshots

default_resource_monitor = ResourceMonitor()
```
No background thread (unlike the legacy version's dedicated monitor loop) —
history only grows when something calls `get_current_usage()` (from
`system_resource_usage()`, `get_telemetry_stats()`, or a test). This is a
deliberate simplification: trends reflect "the last N times this was checked,"
not a fixed wall-clock interval, avoiding an always-running thread for a
resource-monitoring subsystem.

### Component 3: `hexstrike/core/task_pool.py` (new)

```python
class TaskPool:
    def __init__(self, max_workers: int = TASK_POOL_MAX_WORKERS):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def submit(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        spec = ToolRegistry.get(tool_name)
        if spec is None:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}
        task_id = str(uuid.uuid4())
        def run():
            _current_task_id.value = task_id
            try:
                return spec.handler(**params)
            finally:
                _current_task_id.value = None  # clear before thread is reused
        future = self._executor.submit(run)
        with self._lock:
            self._tasks[task_id] = {"tool_name": tool_name, "params": params, "submitted_at": time.time(), "future": future}
            self._prune_old_completed()
        return {"success": True, "task_id": task_id}

    def get_status(self, task_id: str) -> Dict[str, Any]: ...   # queued|running|completed|failed
    def list_tasks(self) -> Dict[str, Any]: ...
    def terminate(self, task_id: str) -> Dict[str, Any]: ...    # see below

default_task_pool = TaskPool()
```
`TASK_POOL_MAX_WORKERS` is a new constant in `hexstrike/core/config.py`
(default 10, matching the legacy `min_workers=4, max_workers=32` range's
rough midpoint without the complexity of making it dynamic).

**`get_status`** inspects the stored `Future`: not `done()` and not
`running()` → `"queued"`; `running()` and not `done()` → `"running"`;
`done()` with `.exception()` → `"failed"` + error string; `done()` clean →
`"completed"` + `.result()`. Always includes `tool_name`, `submitted_at`, and
elapsed seconds.

**`terminate`**: if the future is not yet started, `future.cancel()` (clean,
supported by `concurrent.futures` for not-yet-running work) and mark
`"cancelled"`. If already running, `concurrent.futures` cannot force-stop a
live thread — instead, call `default_process_manager.list_active_processes()`,
filter for entries whose `task_id` matches, and `terminate_process()` each. The
task's status will settle to `"failed"` shortly after (its `run_tool_command`
call returns an error once the subprocess is killed) rather than disappearing
immediately — this asymmetry (instant for queued, "ask nicely, confirm later"
for running) is documented in `task_terminate`'s tool description so a caller
doesn't expect the task to vanish synchronously.

**`_prune_old_completed`**: after each submit, if more than 500 completed/failed
tasks are tracked, drop the oldest ones by `submitted_at` (never prunes
queued/running tasks) — bounds memory for a long-lived server, mirroring the
legacy `PerformanceDashboard`'s `max_history = 1000` cap.

### Component 4: `hexstrike/tools/process_management.py` (new), category `process`

Eleven thin `@ToolRegistry.register` wrappers delegating to Components 1-3:
`task_submit`, `task_status`, `task_list`, `task_terminate`, `process_list`,
`process_status`, `process_terminate`, `process_pause`, `process_resume`,
`system_resource_usage`, `system_telemetry`. Each follows the existing
`webtest.py`/`intelligence.py` return-shape convention (`{"success": ..., ...}`
dicts, no `run_tool_command` involved since these don't shell out themselves).
Registered in `hexstrike/tools/__init__.py` alongside the other category
modules.

## Testing Plan

- **Regression safety net (highest priority):** every existing test in
  `tests/test_process.py` must pass unchanged after the `Popen` refactor —
  these already cover caching, timeout, stdin, and cwd behavior and are the
  proof that the internal swap didn't change observable behavior.
- **New `tests/test_process.py` cases:** registry entries appear during a
  slow command (e.g. `sleep 2`) and disappear after; `terminate_process` on a
  running `sleep 30` actually kills it (assert wall-clock return well under
  30s); `pause_process`/`resume_process` round-trip on a long-running command
  (assert it makes no progress while paused, resumes after); telemetry
  counters increment correctly across success/failure/cache-hit paths.
- **New `tests/test_resource_monitor.py`:** mock `psutil` calls, verify
  returned shape and that `get_usage_trends()` aggregates only what's been
  recorded so far (including the `len(history) < 2` empty case).
- **New `tests/test_task_pool.py`:** submit + poll to completion; unknown
  `tool_name` returns an error without creating a task; unknown `task_id` in
  `get_status`/`terminate`; **a concurrency proof** — submit three tasks each
  wrapping a tool whose handler is monkeypatched to `time.sleep(1)`, assert
  total wall-clock is close to 1s, not 3s, demonstrating real parallelism, not
  serialized execution; terminate a queued (not-yet-started) task vs. a
  running one, asserting the documented status-timing difference.
- **New `tests/test_process_management_tools.py`:** the 11 registered tools,
  mirroring existing per-category test file conventions (registry lookup,
  category count, handler invocation with mocked internals where a real
  subprocess isn't needed).

## Rollout

Single PR, one worktree/branch, following this project's established
convention: implement, run the full suite locally (target: 267 existing +
~35-40 new tests, all passing), verify via a real `setup_mcp_server()` call
that the 11 new tools surface correctly with descriptions, open a PR, confirm
CI green before asking for merge (per the two ci-pipeline incidents earlier
in this project's history where a PR was merged before its CI-fixing follow-up
commit landed — always wait for the actual GitHub Actions run to go green on
the exact commit being merged, not just a local run).
