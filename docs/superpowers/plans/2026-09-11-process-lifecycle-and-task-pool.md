# Process Lifecycle Registry + Task Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the process registry/terminate/pause/resume capability every legacy tool execution had (and the current `hexstrike/core/process.py:ProcessManager` lacks), add a safe background task-submit/poll interface restricted to already-registered `ToolRegistry` tools, and port `ResourceMonitor` + `TelemetryCollector`, exposing all of it as 11 new MCP/HTTP tools in a new `process` category.

**Architecture:** Extend `hexstrike/core/process.py:ProcessManager` in place (refactor its internal `subprocess.run()` call to `subprocess.Popen()` + `communicate()` so a live process reference can be registered and signaled from another thread), add two new sibling modules (`hexstrike/core/resource_monitor.py`, `hexstrike/core/task_pool.py`), and one new tool file (`hexstrike/tools/process_management.py`) that thinly wraps all three. `TaskPool` never runs arbitrary shell strings — it only dispatches to `ToolRegistry.get(tool_name).handler(**params)`, the exact same call every synchronous HTTP/MCP route already makes.

**Tech Stack:** Python 3.13 stdlib only for the new pieces (`concurrent.futures.ThreadPoolExecutor`, `threading`, `os`/`signal`, `collections.deque`) plus `psutil` (already a dependency, used by `hexstrike/tools/intelligence.py` and `cve.py`'s test mocks are not needed here — this is the first *real* `psutil` usage in `hexstrike/core`). No new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-09-11-process-lifecycle-and-task-pool-design.md`

## Global Constraints

- **No arbitrary shell execution.** `TaskPool.submit` accepts only a `tool_name` already present in `ToolRegistry` (verified via `ToolRegistry.get(tool_name)`) plus a `params` dict passed as `**kwargs` to `spec.handler`. There is no code path that runs a raw shell string, and no `shell=True` anywhere in this plan.
- **No auto-scaling.** `TaskPool` wraps a fixed-size `ThreadPoolExecutor`; pool size comes from one new config constant, `TASK_POOL_MAX_WORKERS` (default 10, overridable via `HEXSTRIKE_TASK_POOL_MAX_WORKERS` env var, matching every other constant in `hexstrike/core/config.py`).
- **`tests/test_process.py`'s 7 existing tests must pass completely unchanged** after Task 1's `Popen` refactor — they are the regression proof that caching/timeout/stdin/cwd behavior is unaffected. Do not edit that file's existing tests; only add new ones.
- **Registry cleanup must be race-free.** Only the thread that called `execute_command()` (and is blocked in that specific call's `communicate()`) ever calls `.wait()`/`.communicate()`/`.poll()` on a given `Popen` object. Any other thread (e.g. `terminate_process` called from a `task_terminate` request) only ever sends signals (`.terminate()`, `.kill()`, `os.kill(pid, SIGSTOP/SIGCONT)`) and observes the lock-protected registry dict to infer completion — never calls `.wait()`/`.poll()` itself. This avoids two threads racing to reap the same child process's exit status.
- **`pause_process`/`resume_process` are POSIX-only** (`SIGSTOP`/`SIGCONT` don't exist on Windows). Both return `{"success": False, "error": "pause/resume is not supported on Windows"}` immediately when `os.name == "nt"`, without attempting the signal.
- **`ResourceMonitor.get_current_usage()` uses `psutil.cpu_percent(interval=None)`, not `interval=1`.** The legacy version used `interval=1`, which blocks the calling thread for a full second on every call. Since this plan's `get_telemetry_stats()` calls `get_current_usage()` internally (and could be called frequently via `system_telemetry`/`system_resource_usage`), a mandatory 1-second block per call is a real latency problem this plan deliberately avoids. `interval=None` returns the CPU delta since the last call (0.0 on the very first call in a process) — standard non-blocking `psutil` usage for a value sampled repeatedly.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit. Use `pip install -r requirements.txt -r requirements-dev.txt` in a fresh `.venv` per this project's established CI-matching setup.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```
- **PR mergeability**: after opening the PR, wait for and confirm the actual GitHub Actions run on that exact commit is green (`gh run watch <run-id> --exit-status`) before telling the user it's ready to merge. Do not rely on the local test run alone — this project had an incident where a PR was merged before its CI-fixing follow-up commit had actually been pushed and validated.

---

### Task 1: Refactor `ProcessManager.execute_command` from `subprocess.run` to `Popen` + `communicate`

**Files:**
- Modify: `hexstrike/core/process.py:22-93` (the `execute_command` method body)
- Test: `tests/test_process.py` (existing file — do not modify existing tests; this task adds no new tests, it only proves the existing 7 pass unchanged)

**Interfaces:**
- Consumes: nothing new.
- Produces: `ProcessManager.execute_command(...)` — **identical external signature and return shape** to before. No caller-visible change. This task is purely an internal mechanism swap that Task 2 will build on.

**Current code (`hexstrike/core/process.py:42-93`):**
```python
        try:
            run_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            if stdin_input is not None:
                run_kwargs["input"] = stdin_input
            if cwd is not None:
                run_kwargs["cwd"] = cwd
            res = subprocess.run(command, **run_kwargs)
            elapsed = f"{time.time() - start_time:.2f}s"
            success = (res.returncode == 0)
            output = res.stdout
            error = res.stderr if not success else None

            result_data = {
                "success": success,
                "command": cmd_str,
                "output": output,
                "error": error,
                "execution_time": elapsed,
                "cached": False
            }

            if use_cache and success:
                if len(self.cache) >= self.cache_size:
                    oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["timestamp"])
                    del self.cache[oldest_key]
                self.cache[cache_key] = {
                    "success": success,
                    "output": output,
                    "error": error,
                    "timestamp": now
                }

            return result_data

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": f"Command timed out after {timeout} seconds",
                "execution_time": f"{time.time() - start_time:.2f}s",
                "cached": False
            }
        except Exception as exc:
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": str(exc),
                "execution_time": f"{time.time() - start_time:.2f}s",
                "cached": False
            }
```

- [ ] **Step 1: Confirm the baseline is green**

Run: `./.venv/bin/python3 -m pytest tests/test_process.py -v` (create `.venv` first if needed: `python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt -r requirements-dev.txt`)
Expected: 7 passed.

- [ ] **Step 2: Replace the try block with the `Popen`-based version**

Replace the code block shown above (lines 42-93) with:

```python
        proc = None
        try:
            popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if stdin_input is not None:
                popen_kwargs["stdin"] = subprocess.PIPE
            if cwd is not None:
                popen_kwargs["cwd"] = cwd
            proc = subprocess.Popen(command, **popen_kwargs)

            try:
                stdout, stderr = proc.communicate(input=stdin_input, timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise

            elapsed = f"{time.time() - start_time:.2f}s"
            success = (proc.returncode == 0)
            output = stdout
            error = stderr if not success else None

            result_data = {
                "success": success,
                "command": cmd_str,
                "output": output,
                "error": error,
                "execution_time": elapsed,
                "cached": False
            }

            if use_cache and success:
                if len(self.cache) >= self.cache_size:
                    oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["timestamp"])
                    del self.cache[oldest_key]
                self.cache[cache_key] = {
                    "success": success,
                    "output": output,
                    "error": error,
                    "timestamp": now
                }

            return result_data

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": f"Command timed out after {timeout} seconds",
                "execution_time": f"{time.time() - start_time:.2f}s",
                "cached": False
            }
        except Exception as exc:
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": str(exc),
                "execution_time": f"{time.time() - start_time:.2f}s",
                "cached": False
            }
```

Note: `subprocess.run(command, input=X, ...)` is implemented internally as exactly `Popen(command, stdin=PIPE, ...).communicate(input=X)`, so this is behaviorally identical for stdout/stderr/returncode/text-mode decoding — only the object holding the reference to the live process changes (from none, to `proc`, which Task 2 will register).

- [ ] **Step 3: Run the existing test suite to prove zero behavior change**

Run: `./.venv/bin/python3 -m pytest tests/test_process.py -v`
Expected: same 7 tests, all still PASS — `test_process_manager_execution`, `test_process_manager_caching`, `test_process_manager_timeout`, `test_process_manager_stdin_input`, `test_process_manager_stdin_input_cache_key_does_not_collide`, `test_process_manager_cwd`, `test_process_manager_cwd_cache_key_does_not_collide`.

- [ ] **Step 4: Run the full suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all 267 existing tests PASS (no new tests yet).

- [ ] **Step 5: Commit**

```bash
git add hexstrike/core/process.py
git commit -m "$(cat <<'EOF'
refactor(process): swap subprocess.run for Popen+communicate

Pure internal mechanism change, zero observable behavior change -
proven by all 7 existing test_process.py tests passing unchanged.
Needed so Task 2 can register the live Popen object in a process
registry and signal it (terminate/pause/resume) from another thread
while execute_command's own thread is still blocked in communicate().

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 2: Process registry (list/status/terminate/pause/resume)

**Files:**
- Modify: `hexstrike/core/process.py` (add imports, module-level `_current_task_id`, `__init__` additions, registry methods, and registration/deregistration inside `execute_command`)
- Test: `tests/test_process.py` (add new tests; do not touch the 7 existing ones)

**Interfaces:**
- Consumes: `proc` (the `Popen` object from Task 1, available inside `execute_command`).
- Produces (used by Task 5 and Task 6):
  - Module-level `_current_task_id: threading.local` in `hexstrike.core.process`.
  - `ProcessManager.list_active_processes() -> List[Dict[str, Any]]` — each dict: `{"pid": int, "command": str, "status": str, "task_id": Optional[str], "running_time": float}`.
  - `ProcessManager.get_process_status(pid: int) -> Optional[Dict[str, Any]]` — same shape as one list entry, or `None`.
  - `ProcessManager.terminate_process(pid: int, timeout: int = 10) -> Dict[str, Any]` — `{"success": bool, "pid": int, "method": "graceful"|"forced"|"not_found"}`.
  - `ProcessManager.pause_process(pid: int) -> Dict[str, Any]` / `resume_process(pid: int) -> Dict[str, Any]` — `{"success": bool, "pid": int}` or `{"success": False, "error": str}`.

- [ ] **Step 1: Add imports and module-level thread-local**

At the top of `hexstrike/core/process.py`, change:
```python
import time
import subprocess
from typing import List, Dict, Any, Optional
from hexstrike.core.config import COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL
```
to:
```python
import os
import signal
import threading
import time
import subprocess
from typing import List, Dict, Any, Optional
from hexstrike.core.config import COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL

_current_task_id = threading.local()
```

- [ ] **Step 2: Extend `__init__` with the registry and lock**

Change:
```python
    def __init__(self, cache_size: int = CACHE_SIZE, cache_ttl: int = CACHE_TTL):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.cache_hits = 0
        self.cache_misses = 0
```
to:
```python
    def __init__(self, cache_size: int = CACHE_SIZE, cache_ttl: int = CACHE_TTL):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.cache_hits = 0
        self.cache_misses = 0
        self.active_processes: Dict[int, Dict[str, Any]] = {}
        self._registry_lock = threading.RLock()
```

- [ ] **Step 3: Write the failing tests**

Add to `tests/test_process.py`:
```python
import threading
import time as time_module

def test_process_registry_tracks_running_process():
    pm = ProcessManager()
    result_holder = {}

    def run():
        result_holder["result"] = pm.execute_command(["sleep", "1"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time_module.sleep(0.3)
    active = pm.list_active_processes()
    assert len(active) == 1
    assert active[0]["command"] == "sleep 1"
    assert active[0]["status"] == "running"
    t.join()
    assert pm.list_active_processes() == []
    assert result_holder["result"]["success"] is True

def test_process_registry_removes_entry_after_timeout():
    pm = ProcessManager()
    result = pm.execute_command(["sleep", "2"], timeout=1, use_cache=False)
    assert result["success"] is False
    assert pm.list_active_processes() == []

def test_get_process_status_unknown_pid_returns_none():
    pm = ProcessManager()
    assert pm.get_process_status(999999) is None

def test_terminate_process_kills_running_command():
    pm = ProcessManager()
    result_holder = {}

    def run():
        result_holder["result"] = pm.execute_command(["sleep", "30"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time_module.sleep(0.3)
    active = pm.list_active_processes()
    assert len(active) == 1
    pid = active[0]["pid"]

    start = time_module.time()
    outcome = pm.terminate_process(pid, timeout=5)
    elapsed = time_module.time() - start

    assert outcome["success"] is True
    assert outcome["method"] == "graceful"
    assert elapsed < 5
    t.join(timeout=5)
    assert result_holder["result"]["success"] is False

def test_terminate_process_unknown_pid():
    pm = ProcessManager()
    assert pm.terminate_process(999999) == {"success": False, "pid": 999999, "method": "not_found"}

def test_pause_and_resume_process():
    pm = ProcessManager()
    result_holder = {}

    def run():
        result_holder["result"] = pm.execute_command(["sleep", "2"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time_module.sleep(0.3)
    pid = pm.list_active_processes()[0]["pid"]

    pause_result = pm.pause_process(pid)
    assert pause_result == {"success": True, "pid": pid}
    assert pm.get_process_status(pid)["status"] == "paused"

    resume_result = pm.resume_process(pid)
    assert resume_result == {"success": True, "pid": pid}
    assert pm.get_process_status(pid)["status"] == "running"
    t.join(timeout=5)

def test_pause_process_on_unknown_pid():
    pm = ProcessManager()
    result = pm.pause_process(999999)
    assert result["success"] is False
```

- [ ] **Step 4: Run to verify failure**

Run: `./.venv/bin/python3 -m pytest tests/test_process.py -v -k "registry or terminate or pause or resume or get_process_status"`
Expected: FAIL — `AttributeError: 'ProcessManager' object has no attribute 'list_active_processes'`.

- [ ] **Step 5: Implement the registration/deregistration inside `execute_command`**

Change the `try:` block from Task 1 (the `proc = subprocess.Popen(...)` line onward) to register right after `Popen` succeeds and always deregister via `finally`:

```python
        proc = None
        try:
            popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if stdin_input is not None:
                popen_kwargs["stdin"] = subprocess.PIPE
            if cwd is not None:
                popen_kwargs["cwd"] = cwd
            proc = subprocess.Popen(command, **popen_kwargs)

            with self._registry_lock:
                self.active_processes[proc.pid] = {
                    "pid": proc.pid,
                    "command": cmd_str,
                    "start_time": start_time,
                    "status": "running",
                    "task_id": getattr(_current_task_id, "value", None),
                    "process": proc,
                }

            try:
                try:
                    stdout, stderr = proc.communicate(input=stdin_input, timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    raise
            finally:
                with self._registry_lock:
                    self.active_processes.pop(proc.pid, None)
```

The rest of the method (building `elapsed`/`success`/`output`/`error`/`result_data`, the cache-set block, and the two outer `except` clauses) stays exactly as Task 1 left it.

- [ ] **Step 6: Add the registry query/control methods**

Add these methods to `ProcessManager`, after `get_cache_stats`:

```python
    def list_active_processes(self) -> List[Dict[str, Any]]:
        now = time.time()
        with self._registry_lock:
            return [
                {
                    "pid": pid,
                    "command": entry["command"],
                    "status": entry["status"],
                    "task_id": entry["task_id"],
                    "running_time": now - entry["start_time"],
                }
                for pid, entry in self.active_processes.items()
            ]

    def get_process_status(self, pid: int) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._registry_lock:
            entry = self.active_processes.get(pid)
            if entry is None:
                return None
            return {
                "pid": pid,
                "command": entry["command"],
                "status": entry["status"],
                "task_id": entry["task_id"],
                "running_time": now - entry["start_time"],
            }

    def terminate_process(self, pid: int, timeout: int = 10) -> Dict[str, Any]:
        with self._registry_lock:
            entry = self.active_processes.get(pid)
        if entry is None:
            return {"success": False, "pid": pid, "method": "not_found"}

        entry["process"].terminate()
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._registry_lock:
                if pid not in self.active_processes:
                    return {"success": True, "pid": pid, "method": "graceful"}
            time.sleep(0.1)

        with self._registry_lock:
            still_running = pid in self.active_processes
        if still_running:
            entry["process"].kill()
        return {"success": True, "pid": pid, "method": "forced"}

    def pause_process(self, pid: int) -> Dict[str, Any]:
        if os.name == "nt":
            return {"success": False, "error": "pause/resume is not supported on Windows"}
        with self._registry_lock:
            entry = self.active_processes.get(pid)
        if entry is None:
            return {"success": False, "pid": pid, "error": "process not found"}
        try:
            os.kill(pid, signal.SIGSTOP)
        except ProcessLookupError:
            return {"success": False, "pid": pid, "error": "process not found"}
        with self._registry_lock:
            if pid in self.active_processes:
                self.active_processes[pid]["status"] = "paused"
        return {"success": True, "pid": pid}

    def resume_process(self, pid: int) -> Dict[str, Any]:
        if os.name == "nt":
            return {"success": False, "error": "pause/resume is not supported on Windows"}
        with self._registry_lock:
            entry = self.active_processes.get(pid)
        if entry is None:
            return {"success": False, "pid": pid, "error": "process not found"}
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            return {"success": False, "pid": pid, "error": "process not found"}
        with self._registry_lock:
            if pid in self.active_processes:
                self.active_processes[pid]["status"] = "running"
        return {"success": True, "pid": pid}
```

Only the `terminate_process`/`pause_process`/`resume_process`-calling thread sends signals; it never calls `.wait()`/`.poll()` on `entry["process"]` itself — completion is inferred purely from the registry dict, which only the original `execute_command` thread's `finally` block ever mutates on completion. This is what Global Constraints' race-free rule requires.

- [ ] **Step 7: Run tests to verify they pass**

Run: `./.venv/bin/python3 -m pytest tests/test_process.py -v`
Expected: all previous 7 plus these 7 new tests PASS (14 total in this file).

- [ ] **Step 8: Run the full suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: 274 passed (267 + 7 new).

- [ ] **Step 9: Commit**

```bash
git add hexstrike/core/process.py tests/test_process.py
git commit -m "$(cat <<'EOF'
feat(process): restore process registry, terminate, pause, resume

Legacy hexstrike_server.py had a ProcessManager (distinct from this
project's same-named class) wired into every tool execution via
EnhancedCommandExecutor, providing exactly this: register each
subprocess by PID, list/inspect them, terminate (SIGTERM->SIGKILL),
pause/resume (SIGSTOP/SIGCONT). This capability was silently dropped
when this file's ProcessManager was written for the modular package
(kept only the cache). Restored it, race-free: only the thread blocked
in a given command's communicate() ever waits on that Popen object;
terminate/pause/resume only send signals and read the lock-protected
registry, never call wait()/poll() themselves.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 3: `ResourceMonitor`

**Files:**
- Create: `hexstrike/core/resource_monitor.py`
- Test: `tests/test_resource_monitor.py` (create)

**Interfaces:**
- Consumes: `psutil` (already a project dependency).
- Produces (used by Task 4 and Task 6): `ResourceMonitor.get_current_usage() -> Dict[str, Any]` (keys: `cpu_percent`, `memory_percent`, `memory_available_gb`, `disk_percent`, `disk_free_gb`, `network_bytes_sent`, `network_bytes_recv`, `timestamp`), `ResourceMonitor.get_usage_trends() -> Dict[str, Any]` (empty dict if fewer than 2 samples recorded, else `cpu_avg_recent`, `memory_avg_recent`, `measurements`), and module-level singleton `default_resource_monitor`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_resource_monitor.py`:
```python
from hexstrike.core.resource_monitor import ResourceMonitor


class FakeMemory:
    percent = 42.0
    available = 4 * 1024 ** 3


class FakeDisk:
    percent = 55.0
    free = 100 * 1024 ** 3


class FakeNetwork:
    bytes_sent = 1000
    bytes_recv = 2000


def _patch_psutil(monkeypatch, cpu=10.0):
    import hexstrike.core.resource_monitor as rm
    monkeypatch.setattr(rm.psutil, "cpu_percent", lambda interval=None: cpu)
    monkeypatch.setattr(rm.psutil, "virtual_memory", lambda: FakeMemory())
    monkeypatch.setattr(rm.psutil, "disk_usage", lambda path: FakeDisk())
    monkeypatch.setattr(rm.psutil, "net_io_counters", lambda: FakeNetwork())


def test_get_current_usage_shape(monkeypatch):
    _patch_psutil(monkeypatch, cpu=25.0)
    monitor = ResourceMonitor()
    usage = monitor.get_current_usage()
    assert usage["cpu_percent"] == 25.0
    assert usage["memory_percent"] == 42.0
    assert usage["memory_available_gb"] == 4.0
    assert usage["disk_percent"] == 55.0
    assert usage["disk_free_gb"] == 100.0
    assert usage["network_bytes_sent"] == 1000
    assert usage["network_bytes_recv"] == 2000
    assert "timestamp" in usage


def test_get_usage_trends_empty_with_fewer_than_two_samples(monkeypatch):
    _patch_psutil(monkeypatch)
    monitor = ResourceMonitor()
    assert monitor.get_usage_trends() == {}
    monitor.get_current_usage()
    assert monitor.get_usage_trends() == {}


def test_get_usage_trends_averages_recent_samples(monkeypatch):
    monitor = ResourceMonitor()
    import hexstrike.core.resource_monitor as rm
    for cpu in (10.0, 20.0, 30.0):
        _patch_psutil(monkeypatch, cpu=cpu)
        monitor.get_current_usage()
    trends = monitor.get_usage_trends()
    assert trends["measurements"] == 3
    assert trends["cpu_avg_recent"] == 20.0
    assert trends["memory_avg_recent"] == 42.0


def test_history_capped_at_history_size(monkeypatch):
    _patch_psutil(monkeypatch)
    monitor = ResourceMonitor(history_size=3)
    for _ in range(5):
        monitor.get_current_usage()
    assert monitor.get_usage_trends()["measurements"] == 3
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_resource_monitor.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hexstrike.core.resource_monitor'`.

- [ ] **Step 3: Implement `hexstrike/core/resource_monitor.py`**

```python
import time
from collections import deque
from typing import Dict, Any
import psutil


class ResourceMonitor:
    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self._history: deque = deque(maxlen=history_size)

    def get_current_usage(self) -> Dict[str, Any]:
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            usage = {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024 ** 3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 ** 3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time(),
            }
        except Exception as exc:
            usage = {
                "cpu_percent": 0, "memory_percent": 0, "memory_available_gb": 0,
                "disk_percent": 0, "disk_free_gb": 0, "network_bytes_sent": 0,
                "network_bytes_recv": 0, "timestamp": time.time(), "error": str(exc),
            }
        self._history.append(usage)
        return usage

    def get_usage_trends(self) -> Dict[str, Any]:
        if len(self._history) < 2:
            return {}
        recent = list(self._history)[-10:]
        return {
            "cpu_avg_recent": sum(u["cpu_percent"] for u in recent) / len(recent),
            "memory_avg_recent": sum(u["memory_percent"] for u in recent) / len(recent),
            "measurements": len(self._history),
        }


default_resource_monitor = ResourceMonitor()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./.venv/bin/python3 -m pytest tests/test_resource_monitor.py -v`
Expected: 4 passed.

- [ ] **Step 5: Run the full suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: 278 passed (274 + 4 new).

- [ ] **Step 6: Commit**

```bash
git add hexstrike/core/resource_monitor.py tests/test_resource_monitor.py
git commit -m "$(cat <<'EOF'
feat(core): add ResourceMonitor (CPU/memory/disk/network snapshots)

Ported from the legacy monolith's ResourceMonitor, confirmed genuinely
useful and independent of the never-used ProcessPool cluster it lived
next to. Deliberate deviation: uses psutil.cpu_percent(interval=None)
instead of the legacy interval=1, which blocked every call for a full
second - a real latency problem once Task 4's telemetry starts calling
this on every tool execution. History is opportunistic (recorded only
when get_current_usage() is called), not a dedicated background
thread - trends reflect "the last N times someone checked."

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 4: Telemetry counters on `ProcessManager`

**Files:**
- Modify: `hexstrike/core/process.py` (`__init__`, end of `execute_command`, two new methods)
- Test: `tests/test_process.py` (add new tests)

**Interfaces:**
- Consumes: `ResourceMonitor.get_current_usage()` (Task 3, via `hexstrike.core.resource_monitor.default_resource_monitor`).
- Produces (used by Task 6): `ProcessManager.record_telemetry(success: bool, execution_time: float) -> None`, `ProcessManager.get_telemetry_stats() -> Dict[str, Any]` (keys: `uptime_seconds`, `commands_executed`, `success_rate`, `average_execution_time`, `system_metrics`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_process.py`:
```python
def test_telemetry_starts_at_zero():
    pm = ProcessManager()
    stats = pm.get_telemetry_stats()
    assert stats["commands_executed"] == 0
    assert stats["success_rate"] == "0.0%"
    assert stats["average_execution_time"] == "0.00s"
    assert "system_metrics" in stats

def test_telemetry_records_success_and_failure():
    pm = ProcessManager()
    pm.execute_command(["echo", "hi"], use_cache=False)
    pm.execute_command(["false"], use_cache=False)
    stats = pm.get_telemetry_stats()
    assert stats["commands_executed"] == 2
    assert stats["success_rate"] == "50.0%"

def test_telemetry_counts_cache_hits():
    pm = ProcessManager()
    cmd = ["echo", "cached"]
    pm.execute_command(cmd, use_cache=True)
    pm.execute_command(cmd, use_cache=True)
    stats = pm.get_telemetry_stats()
    assert stats["commands_executed"] == 2
    assert stats["success_rate"] == "100.0%"
```

- [ ] **Step 2: Run to verify failure**

Run: `./.venv/bin/python3 -m pytest tests/test_process.py -v -k telemetry`
Expected: FAIL — `AttributeError: 'ProcessManager' object has no attribute 'get_telemetry_stats'`.

- [ ] **Step 3: Add the import, `__init__` state, and recording calls**

Add to the imports at the top of `hexstrike/core/process.py`:
```python
from hexstrike.core.resource_monitor import default_resource_monitor
```

Add to `__init__` (after `self._registry_lock = threading.RLock()`):
```python
        self.telemetry = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time(),
        }
```

Add the recording call to the cache-hit early-return path — change:
```python
        if use_cache and cache_key in self.cache:
            entry = self.cache[cache_key]
            if now - entry["timestamp"] < self.cache_ttl:
                self.cache_hits += 1
                return {
```
to:
```python
        if use_cache and cache_key in self.cache:
            entry = self.cache[cache_key]
            if now - entry["timestamp"] < self.cache_ttl:
                self.cache_hits += 1
                self.record_telemetry(True, 0.0)
                return {
```

Add the recording call right before each of the three `return` statements at the end of `execute_command` (the success path's `return result_data`, the `TimeoutExpired` handler's return, and the generic `Exception` handler's return) — in each case, insert immediately before the `return`:
```python
            self.record_telemetry(result_data["success"], time.time() - start_time)
            return result_data
```
```python
        except subprocess.TimeoutExpired:
            elapsed_seconds = time.time() - start_time
            self.record_telemetry(False, elapsed_seconds)
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": f"Command timed out after {timeout} seconds",
                "execution_time": f"{elapsed_seconds:.2f}s",
                "cached": False
            }
        except Exception as exc:
            elapsed_seconds = time.time() - start_time
            self.record_telemetry(False, elapsed_seconds)
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": str(exc),
                "execution_time": f"{elapsed_seconds:.2f}s",
                "cached": False
            }
```
(Reuse the computed `elapsed_seconds` for both the telemetry call and the `execution_time` string, replacing the previous `f"{time.time() - start_time:.2f}s"` duplicate computation.)

- [ ] **Step 4: Add the two telemetry methods**

Add after `resume_process`:
```python
    def record_telemetry(self, success: bool, execution_time: float) -> None:
        with self._registry_lock:
            self.telemetry["commands_executed"] += 1
            if success:
                self.telemetry["successful_commands"] += 1
            else:
                self.telemetry["failed_commands"] += 1
            self.telemetry["total_execution_time"] += execution_time

    def get_telemetry_stats(self) -> Dict[str, Any]:
        with self._registry_lock:
            executed = self.telemetry["commands_executed"]
            successful = self.telemetry["successful_commands"]
            total_time = self.telemetry["total_execution_time"]
            uptime = time.time() - self.telemetry["start_time"]
        success_rate = f"{(successful / executed * 100):.1f}%" if executed > 0 else "0.0%"
        avg_time = f"{(total_time / executed):.2f}s" if executed > 0 else "0.00s"
        return {
            "uptime_seconds": uptime,
            "commands_executed": executed,
            "success_rate": success_rate,
            "average_execution_time": avg_time,
            "system_metrics": default_resource_monitor.get_current_usage(),
        }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./.venv/bin/python3 -m pytest tests/test_process.py -v`
Expected: 17 passed (14 from Task 2 + 3 new).

- [ ] **Step 6: Run the full suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: 281 passed (278 + 3 new).

- [ ] **Step 7: Commit**

```bash
git add hexstrike/core/process.py tests/test_process.py
git commit -m "$(cat <<'EOF'
feat(process): add telemetry counters (commands, success rate, uptime)

Ported from the legacy TelemetryCollector, confirmed genuinely used by
every legacy tool execution via EnhancedCommandExecutor - unlike the
never-used ProcessPool cluster. ~40 lines, no equivalent existed in
this project. Reuses ResourceMonitor's snapshot for system_metrics
instead of calling psutil a second time.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 5: `TaskPool`

**Files:**
- Modify: `hexstrike/core/config.py` (add `TASK_POOL_MAX_WORKERS`)
- Create: `hexstrike/core/task_pool.py`
- Test: `tests/test_task_pool.py` (create)

**Interfaces:**
- Consumes: `ToolRegistry.get(tool_name)` / `ToolRegistry.register` (from `hexstrike.core.registry`, existing), `_current_task_id` and `default_process_manager` (from `hexstrike.core.process`, Task 2).
- Produces (used by Task 6): `TaskPool(max_workers=...)`, `.submit(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]` (`{"success": True, "task_id": str}` or `{"success": False, "error": str}`), `.get_status(task_id: str) -> Dict[str, Any]`, `.list_tasks() -> Dict[str, Any]`, `.terminate(task_id: str) -> Dict[str, Any]`, and module-level singleton `default_task_pool`.

- [ ] **Step 1: Add the config constant**

Add to `hexstrike/core/config.py`:
```python
TASK_POOL_MAX_WORKERS = int(os.environ.get("HEXSTRIKE_TASK_POOL_MAX_WORKERS", 10))
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_task_pool.py`:
```python
import time
import pytest
from hexstrike.core.task_pool import TaskPool
from hexstrike.core.registry import ToolRegistry, ToolSpec


def _register_temp_tool(monkeypatch, name, handler):
    monkeypatch.setitem(
        ToolRegistry._tools, name,
        ToolSpec(name=name, category="test", description="test", endpoint=f"/test/{name}", handler=handler),
    )


def test_submit_unknown_tool_returns_error_without_creating_task():
    pool = TaskPool(max_workers=2)
    result = pool.submit("does_not_exist", {})
    assert result == {"success": False, "error": "Unknown tool: does_not_exist"}


def test_submit_and_poll_to_completion(monkeypatch):
    def add(a, b):
        return {"success": True, "sum": a + b}
    _register_temp_tool(monkeypatch, "test_add_tool", add)

    pool = TaskPool(max_workers=2)
    submitted = pool.submit("test_add_tool", {"a": 2, "b": 3})
    assert submitted["success"] is True
    task_id = submitted["task_id"]

    deadline = time.time() + 5
    status = pool.get_status(task_id)
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.05)
        status = pool.get_status(task_id)

    assert status["status"] == "completed"
    assert status["result"] == {"success": True, "sum": 5}
    pool._executor.shutdown(wait=True)


def test_get_status_unknown_task_id():
    pool = TaskPool(max_workers=2)
    result = pool.get_status("does-not-exist")
    assert result == {"success": False, "error": "Unknown task_id: does-not-exist"}


def test_failed_task_reports_error(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")
    _register_temp_tool(monkeypatch, "test_boom_tool", boom)

    pool = TaskPool(max_workers=2)
    task_id = pool.submit("test_boom_tool", {})["task_id"]

    deadline = time.time() + 5
    status = pool.get_status(task_id)
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.05)
        status = pool.get_status(task_id)

    assert status["status"] == "failed"
    assert "kaboom" in status["error"]
    pool._executor.shutdown(wait=True)


def test_list_tasks_includes_submitted_task(monkeypatch):
    def add(a, b):
        return {"success": True, "sum": a + b}
    _register_temp_tool(monkeypatch, "test_add_tool_2", add)

    pool = TaskPool(max_workers=2)
    task_id = pool.submit("test_add_tool_2", {"a": 1, "b": 1})["task_id"]
    listing = pool.list_tasks()
    assert listing["success"] is True
    assert any(t["task_id"] == task_id for t in listing["tasks"])
    pool._executor.shutdown(wait=True)


def test_terminate_queued_task_cancels_it(monkeypatch):
    def blocker():
        time.sleep(2)
        return {"success": True}
    _register_temp_tool(monkeypatch, "test_blocker_tool", blocker)

    pool = TaskPool(max_workers=1)
    first = pool.submit("test_blocker_tool", {})["task_id"]   # occupies the only worker
    second = pool.submit("test_blocker_tool", {})["task_id"]  # stays queued

    result = pool.terminate(second)
    assert result["status"] == "cancelled"
    assert pool.get_status(second)["status"] == "cancelled"
    pool._executor.shutdown(wait=False)


def test_tasks_run_concurrently_not_serially(monkeypatch):
    def sleep_tool(delay):
        time.sleep(delay)
        return {"success": True, "slept": delay}
    _register_temp_tool(monkeypatch, "test_sleep_tool", sleep_tool)

    pool = TaskPool(max_workers=5)
    start = time.time()
    task_ids = [pool.submit("test_sleep_tool", {"delay": 1.0})["task_id"] for _ in range(3)]

    deadline = time.time() + 5
    while any(pool.get_status(tid)["status"] in ("queued", "running") for tid in task_ids) and time.time() < deadline:
        time.sleep(0.05)
    elapsed = time.time() - start

    assert all(pool.get_status(tid)["status"] == "completed" for tid in task_ids)
    assert elapsed < 2.0  # would be ~3s if run serially
    pool._executor.shutdown(wait=True)


def test_terminate_running_task_kills_underlying_process(monkeypatch):
    from hexstrike.core.process import default_process_manager

    def run_sleep():
        return default_process_manager.execute_command(["sleep", "10"], use_cache=False)
    _register_temp_tool(monkeypatch, "test_run_sleep_tool", run_sleep)

    pool = TaskPool(max_workers=2)
    task_id = pool.submit("test_run_sleep_tool", {})["task_id"]
    time.sleep(0.3)  # let the subprocess actually start and register

    result = pool.terminate(task_id)
    assert result["status"] == "termination_requested"
    assert len(result["killed_pids"]) == 1

    deadline = time.time() + 5
    status = pool.get_status(task_id)
    while status["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)
        status = pool.get_status(task_id)
    assert status["status"] == "completed"
    assert status["result"]["success"] is False
    pool._executor.shutdown(wait=True)
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_task_pool.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hexstrike.core.task_pool'`.

- [ ] **Step 3: Implement `hexstrike/core/task_pool.py`**

```python
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.config import TASK_POOL_MAX_WORKERS
from hexstrike.core.process import _current_task_id, default_process_manager


class TaskPool:
    def __init__(self, max_workers: int = TASK_POOL_MAX_WORKERS):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def submit(self, tool_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        spec = ToolRegistry.get(tool_name)
        if spec is None:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        task_id = str(uuid.uuid4())
        call_params = params or {}

        def run():
            _current_task_id.value = task_id
            try:
                return spec.handler(**call_params)
            finally:
                _current_task_id.value = None

        future = self._executor.submit(run)
        with self._lock:
            self._tasks[task_id] = {
                "tool_name": tool_name,
                "params": call_params,
                "submitted_at": time.time(),
                "future": future,
            }
            self._prune_old_completed()
        return {"success": True, "task_id": task_id}

    def _task_view(self, task_id: str, entry: Dict[str, Any]) -> Dict[str, Any]:
        future = entry["future"]
        view = {
            "task_id": task_id,
            "tool_name": entry["tool_name"],
            "submitted_at": entry["submitted_at"],
            "elapsed_seconds": time.time() - entry["submitted_at"],
        }
        if future.cancelled():
            view["status"] = "cancelled"
        elif future.done():
            exc = future.exception()
            if exc is not None:
                view["status"] = "failed"
                view["error"] = str(exc)
            else:
                view["status"] = "completed"
                view["result"] = future.result()
        elif future.running():
            view["status"] = "running"
        else:
            view["status"] = "queued"
        return view

    def get_status(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            entry = self._tasks.get(task_id)
        if entry is None:
            return {"success": False, "error": f"Unknown task_id: {task_id}"}
        return {"success": True, **self._task_view(task_id, entry)}

    def list_tasks(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._tasks.items())
        return {"success": True, "tasks": [self._task_view(tid, e) for tid, e in items]}

    def terminate(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            entry = self._tasks.get(task_id)
        if entry is None:
            return {"success": False, "error": f"Unknown task_id: {task_id}"}

        future = entry["future"]
        if future.cancel():
            return {"success": True, "task_id": task_id, "status": "cancelled"}
        if future.done():
            return {"success": True, "task_id": task_id, "status": self._task_view(task_id, entry)["status"]}

        killed = []
        for proc_info in default_process_manager.list_active_processes():
            if proc_info["task_id"] == task_id:
                default_process_manager.terminate_process(proc_info["pid"])
                killed.append(proc_info["pid"])
        return {"success": True, "task_id": task_id, "status": "termination_requested", "killed_pids": killed}

    def _prune_old_completed(self, max_completed: int = 500) -> None:
        completed = [(tid, e) for tid, e in self._tasks.items() if e["future"].done()]
        if len(completed) <= max_completed:
            return
        completed.sort(key=lambda item: item[1]["submitted_at"])
        for tid, _ in completed[: len(completed) - max_completed]:
            del self._tasks[tid]


default_task_pool = TaskPool()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./.venv/bin/python3 -m pytest tests/test_task_pool.py -v`
Expected: 8 passed. (Note: `test_tasks_run_concurrently_not_serially` and `test_terminate_running_task_kills_underlying_process` are the two that would fail first if `max_workers` weren't actually honored or if termination didn't reach the real subprocess — pay attention if either is slow/flaky rather than clean-failing, and re-run once to rule out CI/host scheduling noise before treating a single flake as a real bug.)

- [ ] **Step 5: Run the full suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: 289 passed (281 + 8 new).

- [ ] **Step 6: Commit**

```bash
git add hexstrike/core/config.py hexstrike/core/task_pool.py tests/test_task_pool.py
git commit -m "$(cat <<'EOF'
feat(core): add TaskPool for background tool execution

ThreadPoolExecutor-based submit/status/list/terminate, dispatching
only to tools already in ToolRegistry (spec.handler(**params) - the
exact same call every synchronous HTTP/MCP route already makes, never
an arbitrary shell string). Fixed-size pool (TASK_POOL_MAX_WORKERS,
default 10) - no auto-scaling, per the design spec's explicit scope
cut (legacy's CPU/memory thresholds were never validated and add
timing-dependent test complexity for uncertain benefit).

Terminating a running (not queued) task can't force-stop its Python
thread - concurrent.futures has no safe mechanism for that - so it
instead finds the OS subprocess(es) tagged with that task_id (via
process.py's _current_task_id thread-local, Task 2's registry) and
kills those; the task's status settles to "failed" shortly after
rather than disappearing synchronously.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

---

### Task 6: `process_management` tools (category `process`)

**Files:**
- Create: `hexstrike/tools/process_management.py`
- Modify: `hexstrike/tools/__init__.py` (add `process_management` to the import line)
- Test: `tests/test_process_management_tools.py` (create)

**Interfaces:**
- Consumes: `default_task_pool` (Task 5), `default_process_manager` (Task 2/4), `default_resource_monitor` (Task 3), `ToolRegistry.register` (existing).
- Produces: 11 registered tools in category `"process"`: `task_submit`, `task_status`, `task_list`, `task_terminate`, `process_list`, `process_status`, `process_terminate`, `process_pause`, `process_resume`, `system_resource_usage`, `system_telemetry`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_process_management_tools.py`:
```python
import time
import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools


def test_process_category_has_11_tools():
    tools = ToolRegistry.get_by_category("process")
    assert len(tools) == 11
    names = {t.name for t in tools}
    assert names == {
        "task_submit", "task_status", "task_list", "task_terminate",
        "process_list", "process_status", "process_terminate",
        "process_pause", "process_resume",
        "system_resource_usage", "system_telemetry",
    }


def test_task_submit_and_status_round_trip():
    submit_tool = ToolRegistry.get("task_submit")
    status_tool = ToolRegistry.get("task_status")

    submitted = submit_tool.handler(tool_name="strings_scan", params={"file_path": "/etc/hostname"})
    assert submitted["success"] is True
    task_id = submitted["task_id"]

    deadline = time.time() + 5
    status = status_tool.handler(task_id=task_id)
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.05)
        status = status_tool.handler(task_id=task_id)

    assert status["status"] == "completed"
    assert status["result"]["success"] is True


def test_task_submit_unknown_tool():
    submit_tool = ToolRegistry.get("task_submit")
    result = submit_tool.handler(tool_name="not_a_real_tool")
    assert result["success"] is False


def test_task_status_unknown_id():
    status_tool = ToolRegistry.get("task_status")
    result = status_tool.handler(task_id="nope")
    assert result["success"] is False


def test_task_list_returns_tasks():
    list_tool = ToolRegistry.get("task_list")
    result = list_tool.handler()
    assert result["success"] is True
    assert isinstance(result["tasks"], list)


def test_process_list_and_status_and_terminate(monkeypatch):
    from hexstrike.core.process import default_process_manager
    import threading

    def run():
        default_process_manager.execute_command(["sleep", "5"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time.sleep(0.3)

    list_tool = ToolRegistry.get("process_list")
    listing = list_tool.handler()
    assert listing["success"] is True
    assert len(listing["processes"]) == 1
    pid = listing["processes"][0]["pid"]

    status_tool = ToolRegistry.get("process_status")
    status = status_tool.handler(pid=pid)
    assert status["success"] is True
    assert status["pid"] == pid

    terminate_tool = ToolRegistry.get("process_terminate")
    result = terminate_tool.handler(pid=pid)
    assert result["success"] is True
    t.join(timeout=5)


def test_process_status_unknown_pid():
    status_tool = ToolRegistry.get("process_status")
    result = status_tool.handler(pid=999999)
    assert result["success"] is False


def test_system_resource_usage_tool():
    tool = ToolRegistry.get("system_resource_usage")
    result = tool.handler()
    assert result["success"] is True
    assert "cpu_percent" in result["usage"]


def test_system_telemetry_tool():
    tool = ToolRegistry.get("system_telemetry")
    result = tool.handler()
    assert result["success"] is True
    assert "commands_executed" in result
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_process_management_tools.py -v`
Expected: FAIL — `ModuleNotFoundError` or `AttributeError: 'NoneType' object has no attribute 'handler'` (tools not registered yet).

- [ ] **Step 3: Implement `hexstrike/tools/process_management.py`**

```python
from typing import Dict, Any, Optional, Annotated
from pydantic import Field
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
from hexstrike.core.resource_monitor import default_resource_monitor
from hexstrike.core.task_pool import default_task_pool


@ToolRegistry.register(
    name="task_submit",
    category="process",
    description="Run a registered tool in the background and return a task_id immediately instead of blocking until it finishes - poll with task_status. Only tools already in the registry can be submitted, never an arbitrary shell command.",
    endpoint="/api/tools/task-submit"
)
def task_submit(
    tool_name: Annotated[str, Field(description="Name of a registered tool to run, e.g. 'nmap_scan' (must already exist in the tool registry)")],
    params: Annotated[Optional[Dict[str, Any]], Field(description="Keyword arguments to pass to the tool, e.g. {'target': '10.0.0.5'}")] = None,
) -> Dict[str, Any]:
    return default_task_pool.submit(tool_name, params or {})


@ToolRegistry.register(
    name="task_status",
    category="process",
    description="Check the status of a task submitted via task_submit: queued, running, completed (with result), failed (with error), or cancelled",
    endpoint="/api/tools/task-status"
)
def task_status(
    task_id: Annotated[str, Field(description="task_id returned by task_submit")],
) -> Dict[str, Any]:
    return default_task_pool.get_status(task_id)


@ToolRegistry.register(
    name="task_list",
    category="process",
    description="List all tasks submitted via task_submit in this server process, with their current status",
    endpoint="/api/tools/task-list"
)
def task_list() -> Dict[str, Any]:
    return default_task_pool.list_tasks()


@ToolRegistry.register(
    name="task_terminate",
    category="process",
    description="Cancel a queued task, or kill the OS subprocess(es) a running task spawned. A running task's status settles to 'failed' shortly after this call, not instantly - it is not force-killed synchronously.",
    endpoint="/api/tools/task-terminate"
)
def task_terminate(
    task_id: Annotated[str, Field(description="task_id returned by task_submit")],
) -> Dict[str, Any]:
    return default_task_pool.terminate(task_id)


@ToolRegistry.register(
    name="process_list",
    category="process",
    description="List every subprocess currently running through this server, from any tool call (synchronous or via task_submit), with PID, command, and running time",
    endpoint="/api/tools/process-list"
)
def process_list() -> Dict[str, Any]:
    return {"success": True, "processes": default_process_manager.list_active_processes()}


@ToolRegistry.register(
    name="process_status",
    category="process",
    description="Get the status of one running subprocess by PID (see process_list)",
    endpoint="/api/tools/process-status"
)
def process_status(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    status = default_process_manager.get_process_status(pid)
    if status is None:
        return {"success": False, "error": f"No active process with pid {pid}"}
    return {"success": True, **status}


@ToolRegistry.register(
    name="process_terminate",
    category="process",
    description="Terminate a running subprocess by PID - SIGTERM first, SIGKILL if it hasn't exited within 10 seconds",
    endpoint="/api/tools/process-terminate"
)
def process_terminate(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    return default_process_manager.terminate_process(pid)


@ToolRegistry.register(
    name="process_pause",
    category="process",
    description="Pause a running subprocess by PID via SIGSTOP - POSIX only, fails on Windows",
    endpoint="/api/tools/process-pause"
)
def process_pause(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    return default_process_manager.pause_process(pid)


@ToolRegistry.register(
    name="process_resume",
    category="process",
    description="Resume a paused subprocess by PID via SIGCONT - POSIX only, fails on Windows",
    endpoint="/api/tools/process-resume"
)
def process_resume(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    return default_process_manager.resume_process(pid)


@ToolRegistry.register(
    name="system_resource_usage",
    category="process",
    description="Snapshot of current CPU/memory/disk/network usage on the machine running this server, plus a short rolling trend",
    endpoint="/api/tools/system-resource-usage"
)
def system_resource_usage() -> Dict[str, Any]:
    return {
        "success": True,
        "usage": default_resource_monitor.get_current_usage(),
        "trends": default_resource_monitor.get_usage_trends(),
    }


@ToolRegistry.register(
    name="system_telemetry",
    category="process",
    description="Aggregate execution statistics across every tool call this server has handled: total commands, success rate, average execution time, uptime",
    endpoint="/api/tools/system-telemetry"
)
def system_telemetry() -> Dict[str, Any]:
    return {"success": True, **default_process_manager.get_telemetry_stats()}
```

- [ ] **Step 4: Register the module**

In `hexstrike/tools/__init__.py`, change:
```python
from hexstrike.tools import network, web, binary, password, osint, cloud, forensics, exploitation, http_framework, browser, webtest, intelligence, cve
```
to:
```python
from hexstrike.tools import network, web, binary, password, osint, cloud, forensics, exploitation, http_framework, browser, webtest, intelligence, cve, process_management
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./.venv/bin/python3 -m pytest tests/test_process_management_tools.py -v`
Expected: 9 passed.

- [ ] **Step 6: Run the full suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: 298 passed (289 + 9 new).

- [ ] **Step 7: Verify the MCP schema surfaces the new tools correctly**

Run:
```bash
./.venv/bin/python3 - <<'EOF'
import asyncio
from hexstrike.mcp.client import HexStrikeClient
from hexstrike.mcp.server import setup_mcp_server
from hexstrike.core.registry import ToolRegistry

print("total tools:", len(ToolRegistry.get_all_tools()))
client = HexStrikeClient(server_url="http://x")
mcp = setup_mcp_server(client)

async def main():
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    expected = {"task_submit", "task_status", "task_list", "task_terminate",
                "process_list", "process_status", "process_terminate",
                "process_pause", "process_resume", "system_resource_usage", "system_telemetry"}
    assert expected <= names, expected - names
    print("all 11 process tools present in MCP schema")

asyncio.run(main())
EOF
```
Expected: `total tools: 116` and `all 11 process tools present in MCP schema` printed, no assertion error.

- [ ] **Step 8: Commit**

```bash
git add hexstrike/tools/process_management.py hexstrike/tools/__init__.py tests/test_process_management_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): register 11 process-management tools (category "process")

Thin wrappers over Tasks 2-5's ProcessManager/ResourceMonitor/TaskPool:
task_submit/status/list/terminate for background execution,
process_list/status/terminate/pause/resume for the restored process
registry, system_resource_usage/system_telemetry for observability.
Registry now has 116 tools (105 + 11). Completes Phase 3 of the
intelligence-layer port.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
EOF
)"
```

- [ ] **Step 9: Push, open PR, confirm CI green**

```bash
git push -u origin process-lifecycle-design
```
Open the PR with `gh pr create --title "feat(tools): process lifecycle registry + task pool (Phase 3)" --body "$(cat <<'EOF' ... EOF)"`, following the Markdown structure every prior PR this session used (`## Summary` bullet list covering each of the 6 tasks' one-line outcome, referencing the spec at `docs/superpowers/specs/2026-09-11-process-lifecycle-and-task-pool-design.md` and its audit finding — the real vs. never-used `ProcessManager` distinction — since that's the non-obvious rationale a reviewer needs; `## Test plan` checklist covering the full local suite count reached (298), the MCP-schema verification from Step 7, and "CI green on this exact commit before merge"). Then poll `gh run list --branch process-lifecycle-design --limit 3 --json databaseId,status,conclusion,event` for the `pull_request` run, and `gh run watch <id> --exit-status` until it reports success on this exact commit before telling the user the PR is ready to merge.

---

## Self-Review Notes (for whoever executes this plan)

- **Spec coverage:** every component in the spec's Architecture section (ProcessManager extension, ResourceMonitor, TaskPool, process_management.py's 11 tools) has a task. The spec's Testing Plan items are all represented: regression safety net (Task 1), registry+kill+pause tests (Task 2), resource monitor tests (Task 3), concurrency proof and termination-reaches-the-real-subprocess test (Task 5), tool-wrapper tests (Task 6).
- **Explicitly out of scope, confirmed not needed here:** `FileOperationsManager` and every bucket (b)/(c)/(d) class from the spec's audit — no task references them, consistent with the spec's Non-Goals.
- **Type/name consistency check:** `_current_task_id` (Task 2) is imported by name in Task 5; `default_process_manager`/`default_resource_monitor`/`default_task_pool` singleton names are used identically across Tasks 2-6; `ToolSpec` (used in Task 5's test) matches `hexstrike/core/registry.py`'s existing dataclass fields (`name, category, description, endpoint, handler`).
