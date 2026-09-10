# libc-database Tool Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `cwd` support to the shared process-execution layer (`hexstrike/core/process.py`'s `ProcessManager.execute_command` and `hexstrike/tools/base.py`'s `run_tool_command`), then use it to port `libc_database_lookup` — the last tool explicitly deferred by the binary-advanced-tools-migration plan for exactly this reason. Extends `binary` from 14 to 15 tools.

**Why this needed its own infra change:** legacy's `libc-database` endpoint is a genuine shell pipeline: `cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo 'libc-database not found' && ./{action} {args}`. There is no `List[str]` equivalent of `cd` — the closest faithful adaptation is resolving the target directory in Python and running the subcommand with `subprocess.run(..., cwd=...)`, which `ProcessManager.execute_command` did not support before this plan (confirmed by inspection when `libc-database` was first deferred in `docs/superpowers/plans/2026-09-10-binary-advanced-tools-migration.md`).

**Architecture:** `ProcessManager.execute_command` gains a `cwd: Optional[str] = None` parameter, forwarded to `subprocess.run(..., cwd=cwd)` (Python's `subprocess.run` runs the child process in `cwd` when given, and in the caller's own current directory when `None` — matching legacy's behavior when neither `/opt/libc-database` nor `~/libc-database` exists: the `cd` commands fail, `echo` prints a message but still exits 0, and `./​{action}` then runs in the *server's own* current directory since no `cd` actually took effect). `run_tool_command` gains the same parameter and forwards it through.

**Tech Stack:** Python 3.13, pytest, `pathlib.Path` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`. Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`. Prior deferral note: `docs/superpowers/plans/2026-09-10-binary-advanced-tools-migration.md`'s "Explicit scope boundary" section.

## Global Constraints

- **No shell strings**: `cwd` is passed as a plain string to `subprocess.run(..., cwd=cwd)`; no `cd`, no `&&`, no `||`, no `shell=True`.
- **Cache-key correctness**: mirrors the `stdin_input` fix from the prior stdin-support-tools-migration plan — two calls with identical argv but different `cwd` could otherwise collide in `ProcessManager`'s cache (e.g. `["./find", "symbol1"]` run in two different libc-database installs would be indistinguishable by argv alone). `_get_cache_key` incorporates `cwd` the same way it already incorporates `stdin_input`.
- **Directory resolution happens in Python, not the subprocess layer**: `libc_database_lookup` itself decides between `/opt/libc-database`, `~/libc-database`, or `None` (current directory) — `ProcessManager` only needs to know how to run a command in an already-resolved directory; it has no opinion on what that directory should be.
- **Legacy's action-based branching is not exhaustively validated**: legacy also validated `symbols` (for `find`) and `libc_id` (for `dump`/`download`) are non-empty (400 otherwise), and returned 400 for an unrecognized `action`. Per the established precedent (`steghide_run` in `forensics.py`, the `avoid the enum-value 400` note repeated across every plan since), this plan implements only the three valid `action` branches as `if/elif/elif` with no trailing `else` and does not re-add the `symbols`/`libc_id` presence checks — an invalid `action` leaves `cmd` unbound (`NameError` → 500 via the generic handler), and a missing `symbols`/`libc_id` is passed through as `None` to the underlying CLI tool rather than rejected early.
- **`additional_args` handling**: `Optional[str] = None`, appended via `additional_args.split()`, always last.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: Add `cwd` support to `ProcessManager.execute_command` and `run_tool_command`

**Files:**
- Modify: `hexstrike/core/process.py`
- Modify: `hexstrike/tools/base.py`
- Test: `tests/test_process.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_process.py`:

```python
def test_process_manager_cwd():
    pm = ProcessManager()
    result = pm.execute_command(["pwd"], cwd="/tmp", use_cache=False)
    assert result["success"] is True
    assert result["output"].strip() == "/tmp"

def test_process_manager_cwd_cache_key_does_not_collide():
    pm = ProcessManager()
    r1 = pm.execute_command(["pwd"], cwd="/tmp", use_cache=True)
    r2 = pm.execute_command(["pwd"], cwd="/", use_cache=True)
    assert r1["output"].strip() == "/tmp"
    assert r2["output"].strip() == "/"
    assert r2["cached"] is False
```

- [ ] **Step 2: Run test to verify it fails** — `TypeError: execute_command() got an unexpected keyword argument 'cwd'`.

- [ ] **Step 3: Write minimal implementation**

In `hexstrike/core/process.py`, extend the cache key and `execute_command` signature (same shape as the existing `stdin_input` parameter added in the stdin-support-tools-migration plan):

```python
def _get_cache_key(self, command: List[str], stdin_input: Optional[str] = None, cwd: Optional[str] = None) -> str:
    key = " ".join(command)
    if stdin_input is not None:
        key += f"\x00{stdin_input}"
    if cwd is not None:
        key += f"\x00cwd={cwd}"
    return key

def execute_command(self, command: List[str], timeout: int = COMMAND_TIMEOUT, use_cache: bool = True, stdin_input: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    cmd_str = " ".join(command)
    cache_key = self._get_cache_key(command, stdin_input, cwd)
    now = time.time()

    if use_cache and cache_key in self.cache:
        entry = self.cache[cache_key]
        if now - entry["timestamp"] < self.cache_ttl:
            self.cache_hits += 1
            return {
                "success": entry["success"],
                "command": cmd_str,
                "output": entry["output"],
                "error": entry.get("error"),
                "execution_time": "0.00s",
                "cached": True
            }

    self.cache_misses += 1
    start_time = time.time()
    try:
        run_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if stdin_input is not None:
            run_kwargs["input"] = stdin_input
        if cwd is not None:
            run_kwargs["cwd"] = cwd
        res = subprocess.run(command, **run_kwargs)
        # ...unchanged from here (success/output/error/caching/exception handling)
```

(Only the `_get_cache_key` signature, the `cache_key` computation, and the `run_kwargs["cwd"] = cwd` line change — everything else in the method body is unchanged.)

In `hexstrike/tools/base.py`:

```python
def run_tool_command(command: List[str], timeout: int = 300, use_cache: bool = True, stdin_input: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    tool_binary = command[0]
    if not is_tool_available(tool_binary):
        return {
            "success": False,
            "command": " ".join(command),
            "output": "",
            "error": f"Tool binary '{tool_binary}' not found on system PATH",
            "execution_time": "0.00s",
            "cached": False
        }
    return default_process_manager.execute_command(command, timeout=timeout, use_cache=use_cache, stdin_input=stdin_input, cwd=cwd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(core): add cwd support to ProcessManager and run_tool_command`)

---

### Task 2: `libc_database_lookup`

**Legacy (`d689933:hexstrike_server.py:10654...` — see prior deferral note for exact source):** resolves `/opt/libc-database` or `~/libc-database` via a shell `cd ... || cd ... || echo ...`, then runs `./find`/`./dump`/`./download` in that directory (or the server's own cwd if neither resolved) with `&&`.

**Produces:** `libc_database_lookup(action="find", symbols=None, libc_id=None, additional_args=None)` → `"libc_database_lookup"` at `/api/tools/libc-database`, category `"binary"`.

- [ ] **Step 1: Write the failing test**

```python
def test_libc_database_lookup_handler_invocation_find(monkeypatch, tmp_path):
    resolved_dir = tmp_path / "libc-database"
    resolved_dir.mkdir()
    monkeypatch.setattr("hexstrike.tools.binary.Path", Path)  # sanity: real Path, patched below via isdir target
    # Force directory resolution to hit the /opt path by patching Path.is_dir for the exact target
    real_is_dir = Path.is_dir
    def fake_is_dir(self):
        if str(self) == "/opt/libc-database":
            return True
        return real_is_dir(self)
    monkeypatch.setattr(Path, "is_dir", fake_is_dir)

    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("libc_database_lookup")
    assert tool is not None
    assert tool.endpoint == "/api/tools/libc-database"

    res = tool.handler(action="find", symbols="printf:0x64 system:0x123", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["./find", "printf:0x64 system:0x123", "-v"]
    assert captured["kwargs"]["cwd"] == "/opt/libc-database"


def test_libc_database_lookup_handler_invocation_dump_home_fallback(monkeypatch):
    real_is_dir = Path.is_dir
    def fake_is_dir(self):
        if str(self) == "/opt/libc-database":
            return False
        if str(self) == str(Path.home() / "libc-database"):
            return True
        return real_is_dir(self)
    monkeypatch.setattr(Path, "is_dir", fake_is_dir)

    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("libc_database_lookup")
    res = tool.handler(action="dump", libc_id="libc6_2.31-0ubuntu9_amd64")
    assert res["success"] is True
    assert captured["cmd"] == ["./dump", "libc6_2.31-0ubuntu9_amd64"]
    assert captured["kwargs"]["cwd"] == str(Path.home() / "libc-database")


def test_libc_database_lookup_handler_invocation_download_neither_dir_found(monkeypatch):
    monkeypatch.setattr(Path, "is_dir", lambda self: False)

    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("libc_database_lookup")
    res = tool.handler(action="download", libc_id="abc123")
    assert res["success"] is True
    assert captured["cmd"] == ["./download", "abc123"]
    assert captured["kwargs"]["cwd"] is None
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

Add to `hexstrike/tools/binary.py` (needs `Optional[Dict[str, Any]]` already imported; no new imports beyond what's already there — `Path` is already imported):

```python
def _resolve_libc_database_dir() -> Optional[str]:
    if Path("/opt/libc-database").is_dir():
        return "/opt/libc-database"
    home_dir = Path.home() / "libc-database"
    if home_dir.is_dir():
        return str(home_dir)
    return None

@ToolRegistry.register(
    name="libc_database_lookup",
    category="binary",
    description="libc identification and offset lookup using libc-database",
    endpoint="/api/tools/libc-database"
)
def libc_database_lookup(action: str = "find", symbols: Optional[str] = None, libc_id: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    if action == "find":
        cmd = ["./find", symbols]
    elif action == "dump":
        cmd = ["./dump", libc_id]
    elif action == "download":
        cmd = ["./download", libc_id]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, cwd=_resolve_libc_database_dir())
```

Note: `run_tool_command`'s `is_tool_available(command[0])` check will look up `./find`/`./dump`/`./download` on `PATH`, which will always fail for a relative path unless it happens to resolve — this mirrors how every other tool's availability check works (`shutil.which`) and is an acceptable, unavoidable side effect of these being repo-relative scripts rather than installed binaries; it is not something this plan needs to special-case (the mocked tests patch `is_tool_available` directly, same as every other test in this codebase).

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 3: Full verification

- [ ] **Step 1: Assert binary category has exactly 15 tools** (add to `tests/test_binary_tools.py`, replacing the existing 14-tool assertion).
- [ ] **Step 2: Run the entire test suite** — all PASS.
- [ ] **Step 3: MCP sanity check** — assert `libc_database_lookup` present in `mcp.list_tools()`.
- [ ] **Step 4: Commit** (`test(tools): verify binary category reaches 15-tool parity`)
