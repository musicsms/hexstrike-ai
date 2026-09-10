# Stdin-Support Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `stdin_input` capability to the shared process-execution layer (`hexstrike/core/process.py`'s `ProcessManager.execute_command` and `hexstrike/tools/base.py`'s `run_tool_command`), then use it to port the 4 tools explicitly deferred across two prior migrations for exactly this reason: `anew_process`, `qsreplace_process`, `uro_filter` (deferred by the web-tools-migration plan) and `pacu_run` (deferred by the cloud-tools-migration plan). Extends `web` from 23 to 26 tools and `cloud` from 11 to 12.

**Why this is one plan, not two:** the infrastructure change has no purpose without a consumer, and the four tools cannot be ported without it — the web plan's own words: "these need that capability added first, as its own plan" and the cloud plan's: "port it alongside those four in that future stdin-support sub-project, not here." This plan is that sub-project.

**Architecture:** `ProcessManager.execute_command` gains an `stdin_input: Optional[str] = None` parameter, forwarded to `subprocess.run(..., input=stdin_input)` when set (Python's `subprocess.run` accepts `input=` as a string and implicitly wires `stdin=PIPE` — no `shell=True`, no manual pipe/file-descriptor plumbing needed). `run_tool_command` gains the same parameter and forwards it through. Each of the four tool functions builds its `List[str]` command as usual and passes the data that legacy piped via `echo '{x}' | tool` (or redirected via `tool < file`, for `pacu`) as `stdin_input` instead.

**Cache-key correctness (the one real risk in this plan):** `ProcessManager`'s cache key today is just `" ".join(command)`. For a stdin-consuming command, the same argv (e.g. `["anew"]`) produces completely different output depending on the piped data — using the existing key would let one caller's cached output leak to a different caller's differently-piped-in data. Fix: `_get_cache_key` incorporates `stdin_input` (when not `None`) into the key, joined by a NUL separator (`\x00`) so it can't collide with legitimate argv text; the `"command"` field returned to callers stays the plain `" ".join(command)` display string, unaffected.

**Tech Stack:** Python 3.13, pytest, `subprocess` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`. Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`. Prior deferral notes: `docs/superpowers/plans/2026-09-09-web-tools-migration.md` (scope boundary section), `docs/superpowers/plans/2026-09-09-cloud-tools-migration.md` (scope boundary section).

## Global Constraints

- **No shell strings, ever** — `stdin_input` is passed as a Python string directly into `subprocess.run(..., input=...)`; there is still no `shell=True` anywhere and no manual quoting/escaping, since the data never passes through a shell.
- **`additional_args` handling**: `Optional[str] = None`, appended via `additional_args.split()`, always last (matching every other tool in this codebase).
- **Legacy manual validation is not reproduced**: `input_data` (anew), `urls` (qsreplace, uro) become required parameters with no default; a missing value raises `TypeError` → 400 via `hexstrike/api/app.py`.
- **`pacu_run` drops the temp-file indirection entirely** — legacy wrote the constructed Pacu command sequence to `/tmp/pacu_commands.txt` and ran `pacu < {file}` only because a shell redirect needs a real file; with `stdin_input` support, the exact same joined-command text is passed directly as the subprocess's stdin, with identical effective behavior (Pacu reads the same bytes from its stdin either way) and no temp file, no cleanup, no `os.remove` needed. This is a genuine simplification enabled by the new capability, not a behavior change — call it out in the commit message, don't hide it.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: Add `stdin_input` support to `ProcessManager.execute_command` and `run_tool_command`

**Files:**
- Modify: `hexstrike/core/process.py`
- Modify: `hexstrike/tools/base.py`
- Test: `tests/test_process.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_process.py`:

```python
def test_process_manager_stdin_input():
    pm = ProcessManager()
    result = pm.execute_command(["cat"], stdin_input="hello from stdin\n", use_cache=False)
    assert result["success"] is True
    assert result["output"] == "hello from stdin\n"

def test_process_manager_stdin_input_cache_key_does_not_collide():
    pm = ProcessManager()
    r1 = pm.execute_command(["cat"], stdin_input="first\n", use_cache=True)
    r2 = pm.execute_command(["cat"], stdin_input="second\n", use_cache=True)
    assert r1["output"] == "first\n"
    assert r2["output"] == "second\n"
    assert r2["cached"] is False  # different stdin_input must not hit r1's cache entry
```

- [ ] **Step 2: Run test to verify it fails** — `TypeError: execute_command() got an unexpected keyword argument 'stdin_input'`.

- [ ] **Step 3: Write minimal implementation**

In `hexstrike/core/process.py`:

```python
def _get_cache_key(self, command: List[str], stdin_input: Optional[str] = None) -> str:
    key = " ".join(command)
    if stdin_input is not None:
        key += f"\x00{stdin_input}"
    return key

def execute_command(self, command: List[str], timeout: int = COMMAND_TIMEOUT, use_cache: bool = True, stdin_input: Optional[str] = None) -> Dict[str, Any]:
    cmd_str = " ".join(command)
    cache_key = self._get_cache_key(command, stdin_input)
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

(Only the two `cmd_str`/cache-key lines at the top, the `run_kwargs` block replacing the bare `subprocess.run(...)` call, and the two `self.cache[cache_key]`/`cache_key in self.cache` substitutions for the previous `cmd_str`-keyed lookups actually change — the rest of the method body is unchanged from today's implementation.)

In `hexstrike/tools/base.py`:

```python
def run_tool_command(command: List[str], timeout: int = 300, use_cache: bool = True, stdin_input: Optional[str] = None) -> Dict[str, Any]:
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
    return default_process_manager.execute_command(command, timeout=timeout, use_cache=use_cache, stdin_input=stdin_input)
```

(Add `Optional` to the existing `from typing import ...` import in `base.py` if not already present.)

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Run the entire test suite**
- [ ] **Step 6: Commit** (`feat(core): add stdin_input support to ProcessManager and run_tool_command`)

---

### Task 2: `anew_process`

**Legacy (`d689933:hexstrike_server.py:13185-13211`):** `echo '{input_data}' | anew {output_file}` (or no trailing arg if `output_file` absent), then `additional_args`.

**Produces:** `anew_process(input_data, output_file=None, additional_args=None)` → `"anew_process"` at `/api/tools/anew`, category `"web"`.

- [ ] **Step 1: Write the failing test**

```python
def test_anew_process_handler_invocation(monkeypatch):
    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("anew_process")
    assert tool is not None
    assert tool.category == "web"
    assert tool.endpoint == "/api/tools/anew"

    res = tool.handler(input_data="line1\nline2", output_file="/tmp/seen.txt", additional_args="-q")
    assert res["success"] is True
    assert captured["cmd"] == ["anew", "/tmp/seen.txt", "-q"]
    assert captured["kwargs"]["stdin_input"] == "line1\nline2"
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="anew_process",
    category="web",
    description="Append new lines to a file, filtering duplicates, using anew",
    endpoint="/api/tools/anew"
)
def anew_process(input_data: str, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["anew"]
    if output_file:
        cmd.append(output_file)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input=input_data)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 3: `qsreplace_process`

**Legacy (`d689933:hexstrike_server.py:13214-13234`):** `echo '{urls}' | qsreplace '{replacement}'`, then `additional_args`.

**Produces:** `qsreplace_process(urls, replacement="FUZZ", additional_args=None)` → `"qsreplace_process"` at `/api/tools/qsreplace`, category `"web"`.

- [ ] **Step 1: Write the failing test**

```python
def test_qsreplace_process_handler_invocation(monkeypatch):
    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("qsreplace_process")
    assert tool is not None
    assert tool.endpoint == "/api/tools/qsreplace"

    res = tool.handler(urls="http://a.com?x=1\nhttp://b.com?y=2", replacement="XSS", additional_args="-appendmode")
    assert res["success"] is True
    assert captured["cmd"] == ["qsreplace", "XSS", "-appendmode"]
    assert captured["kwargs"]["stdin_input"] == "http://a.com?x=1\nhttp://b.com?y=2"
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="qsreplace_process",
    category="web",
    description="Query string parameter replacement using qsreplace",
    endpoint="/api/tools/qsreplace"
)
def qsreplace_process(urls: str, replacement: str = "FUZZ", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["qsreplace", replacement]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input=urls)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 4: `uro_filter`

**Legacy (`d689933:hexstrike_server.py:13237-13262`):** `echo '{urls}' | uro`, then `--whitelist`, `--blacklist`, `additional_args`.

**Produces:** `uro_filter(urls, whitelist=None, blacklist=None, additional_args=None)` → `"uro_filter"` at `/api/tools/uro`, category `"web"`.

- [ ] **Step 1: Write the failing test**

```python
def test_uro_filter_handler_invocation(monkeypatch):
    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("uro_filter")
    assert tool is not None
    assert tool.endpoint == "/api/tools/uro"

    res = tool.handler(urls="http://a.com/1\nhttp://a.com/2", whitelist="a.com", blacklist="b.com", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["uro", "--whitelist", "a.com", "--blacklist", "b.com", "-v"]
    assert captured["kwargs"]["stdin_input"] == "http://a.com/1\nhttp://a.com/2"
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="uro_filter",
    category="web",
    description="Filter out semantically similar URLs using uro",
    endpoint="/api/tools/uro"
)
def uro_filter(urls: str, whitelist: Optional[str] = None, blacklist: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["uro"]
    if whitelist:
        cmd.extend(["--whitelist", whitelist])
    if blacklist:
        cmd.extend(["--blacklist", blacklist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input=urls)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 5: `pacu_run`

**Legacy (`d689933:hexstrike_server.py:10654-10701`):** builds a `\n`-joined Pacu command sequence, writes it to `/tmp/pacu_commands.txt`, runs `pacu < /tmp/pacu_commands.txt`, then deletes the file.

**Produces:** `pacu_run(session_name="hexstrike_session", modules=None, data_services=None, regions=None, additional_args=None)` → `"pacu_run"` at `/api/tools/pacu`, category `"cloud"`. No temp file — the joined command text becomes `stdin_input` directly (see Global Constraints).

- [ ] **Step 1: Write the failing test**

```python
def test_pacu_run_handler_invocation(monkeypatch):
    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("pacu_run")
    assert tool is not None
    assert tool.category == "cloud"
    assert tool.endpoint == "/api/tools/pacu"

    res = tool.handler(session_name="mysess", data_services="s3,ec2", regions="us-east-1", modules="iam__enum_users, s3__bucket_finder", additional_args="--force")
    assert res["success"] is True
    assert captured["cmd"] == ["pacu", "--force"]
    assert captured["kwargs"]["stdin_input"] == (
        "set_session mysess\n"
        "data s3,ec2\n"
        "set_regions us-east-1\n"
        "run iam__enum_users\n"
        "run s3__bucket_finder\n"
        "exit"
    )


def test_pacu_run_handler_invocation_defaults(monkeypatch):
    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("pacu_run")
    res = tool.handler()
    assert res["success"] is True
    assert captured["cmd"] == ["pacu"]
    assert captured["kwargs"]["stdin_input"] == "set_session hexstrike_session\nexit"
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="pacu_run",
    category="cloud",
    description="AWS exploitation framework automation using Pacu",
    endpoint="/api/tools/pacu"
)
def pacu_run(session_name: str = "hexstrike_session", modules: Optional[str] = None, data_services: Optional[str] = None, regions: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    commands = [f"set_session {session_name}"]
    if data_services:
        commands.append(f"data {data_services}")
    if regions:
        commands.append(f"set_regions {regions}")
    if modules:
        for module in modules.split(","):
            commands.append(f"run {module.strip()}")
    commands.append("exit")

    cmd = ["pacu"]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input="\n".join(commands))
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 6: Full verification

- [ ] **Step 1: Assert category counts** — `web` has 26 tools, `cloud` has 12.

```python
def test_web_category_has_26_tools():
    from hexstrike.core.registry import ToolRegistry
    web_tools = ToolRegistry.get_by_category("web")
    assert len(web_tools) == 26

def test_cloud_category_has_12_tools():
    from hexstrike.core.registry import ToolRegistry
    cloud_tools = ToolRegistry.get_by_category("cloud")
    assert len(cloud_tools) == 12
```

(Add these to `tests/test_web_tools.py` and `tests/test_cloud_tools.py` respectively, next to each file's existing category-count test — update the existing `test_web_category_has_23_tools`/similar if the count assertion needs bumping rather than adding a duplicate test with a stale name.)

- [ ] **Step 2: Run the entire test suite** — all PASS.
- [ ] **Step 3: MCP sanity check** — assert `anew_process`, `qsreplace_process`, `uro_filter`, `pacu_run` present in `mcp.list_tools()`.
- [ ] **Step 4: Commit** (`test(tools): verify web/cloud category parity after stdin-support migration`)
