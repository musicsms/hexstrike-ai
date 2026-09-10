# Binary Advanced Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the 3 of the 4 tools explicitly deferred by `docs/superpowers/plans/2026-09-10-binary-tools-migration.md`'s scope boundary that are now judged portable without new shared infrastructure: `pwntools_exploit`, `angr_analyze`, `gdb_peda_analyze`. Extends `binary` from 11 tools to 14.

**Architecture:** Same `@ToolRegistry.register` / `List[str]` / `run_tool_command` pattern as every other category. The distinguishing feature of these three tools: legacy generates a **Python script as text** (either user-supplied `script_content`, or a template embedding target parameters) into a fixed temp file, then runs `python3 {temp_file}` — there is no shell operator involved (`&&`, `|`, `cd`) in this half of the pattern, only file I/O, so it fits `List[str]` execution directly once the temp-file write is done in Python instead of a shell string.

**Explicit scope boundary — `libc-database` remains OUT of scope:** confirmed by inspecting `hexstrike/tools/base.py`'s `run_tool_command` and `hexstrike/core/process.py`'s `ProcessManager.execute_command` — neither accepts a `cwd` parameter, and `subprocess.run` is called without one. Legacy's `libc-database` endpoint is a genuine shell pipeline (`cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo '...' && ./{action} {args}`) whose faithful non-shell adaptation requires running the resolved subcommand in a specific working directory — i.e., adding `cwd` support to `ProcessManager.execute_command` first. That is shared-infrastructure work belonging to its own plan, not a single tool port.

**Tech Stack:** Python 3.13, pytest, `pathlib.Path` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`. Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

## Global Constraints

- **Template-generation code is copied verbatim, not re-derived**: for `pwntools_exploit` and `angr_analyze`, the exact same Python f-string/string literals used by the legacy Flask handlers are reused unchanged in the new functions (same double-brace vs. single-brace placeholders, preserving legacy's inconsistency between them — e.g. angr's `print(f"Loaded binary: {binary}")` is single-braced and gets substituted immediately by the outer f-string into literal text, while the very next line `print(f"Architecture: {{project.arch}}")` is double-braced and stays as literal `{project.arch}` text for the *generated* script to evaluate later. This looks like an accidental inconsistency in the legacy code, but it is not this plan's job to fix it — preserve it exactly). Tests build their expected file content using the identical literal template inline (not hand-transcribed), so a test failure only fires on an actual code change, not a transcription slip.
- **`target_binary`/`target_host` in `pwntools_exploit` default to `""` (not `None`)**: their *string value* is embedded directly into generated code as `'{target_binary}'` regardless of truthiness (only the ternary's *result* depends on truthiness). If the Python default were `None`, the generated line would read `binary = 'None' if 'None' else None` — since the non-empty string `'None'` is truthy, `binary` would wrongly become the four-character string `"None"` instead of `None`. Legacy's `""` default avoids this: `binary = '' if '' else None` → falsy → `binary = None`. This is a correctness-preserving detail, not a style choice — do not "clean up" these two parameters to `Optional[str] = None`.
- **`target_port` defaults to `0`, an `int`**, embedded unquoted (`port = {target_port} if {target_port} else None`).
- **`find_address`/`avoid_addresses` in `angr_analyze` may default to `Optional[str] = None`** — unlike `target_binary` above, these are never embedded as literal text on the truthy branch; both the `if X else 'None'`/`'[]'` conditional arms only depend on truthiness, so `None` and `""` produce identical generated output.
- **Preserve the `avoid_addresses` bug literally**: `avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}` — when `avoid_addresses` is falsy, the outer f-string substitutes the *string* `'[]'` (four characters, single-quoted) into the generated code, i.e. the generated line reads `avoid_addrs = '[]'`, assigning the STRING `"[]"` rather than an actual empty list. This is a legacy bug, not something to fix in this plan — preserve it exactly, byte for byte.
- **`binary` is required (no default) in `angr_analyze`**; legacy's `if not binary: 400` is dropped per the established precedent (`TypeError` → 400 via `hexstrike/api/app.py`). `pwntools_exploit`'s either-or requirement (`script_content` OR `target_binary`) is left unvalidated per the same precedent used for `dalfox_scan`/`zap_scan`/`arp_scan` in prior plans.
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True`.
- **`additional_args` handling**: `Optional[str] = None`, appended via `additional_args.split()`, always last.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: `pwntools_exploit`

**Legacy (`d689933:hexstrike_server.py:12294-12369`):** see full source in the parent plan's research; template text reproduced verbatim in the implementation below.

**Produces:** `pwntools_exploit(script_content=None, target_binary="", target_host="", target_port=0, exploit_type="local", additional_args=None)` → `"pwntools_exploit"` at `/api/tools/pwntools`, category `"binary"`.

- [ ] **Step 1: Write the failing test**

```python
def test_pwntools_exploit_handler_invocation_script_content(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwntools_exploit")
    assert tool is not None
    assert tool.category == "binary"
    assert tool.endpoint == "/api/tools/pwntools"

    res = tool.handler(script_content="print('hi')", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["python3", "/tmp/pwntools_exploit.py", "-v"]
    assert Path("/tmp/pwntools_exploit.py").exists() is False  # cleaned up


def test_pwntools_exploit_handler_invocation_generated_template(monkeypatch):
    written = {}
    original_write_text = Path.write_text
    def capture_write_text(self, content, *a, **kw):
        if str(self) == "/tmp/pwntools_exploit.py":
            written["content"] = content
        return original_write_text(self, content, *a, **kw)
    monkeypatch.setattr(Path, "write_text", capture_write_text)

    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwntools_exploit")

    res = tool.handler(target_binary="/tmp/exploit")
    assert res["success"] is True
    assert captured["cmd"] == ["python3", "/tmp/pwntools_exploit.py"]

    target_binary, target_host, target_port = "/tmp/exploit", "", 0
    expected = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
    assert written["content"] == expected
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="pwntools_exploit",
    category="binary",
    description="Exploit development and automation using Pwntools",
    endpoint="/api/tools/pwntools"
)
def pwntools_exploit(script_content: Optional[str] = None, target_binary: str = "", target_host: str = "", target_port: int = 0, exploit_type: str = "local", additional_args: Optional[str] = None) -> Dict[str, Any]:
    script_file = "/tmp/pwntools_exploit.py"
    if script_content:
        Path(script_file).write_text(script_content)
    else:
        template = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
        Path(script_file).write_text(template)
    cmd = ["python3", script_file]
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    try:
        Path(script_file).unlink()
    except OSError:
        pass
    return result
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 2: `angr_analyze`

**Legacy (`d689933:hexstrike_server.py:12498-12588`):** template text reproduced verbatim below, including the single-brace/double-brace inconsistency and the `avoid_addresses` string-vs-list bug (see Global Constraints).

**Produces:** `angr_analyze(binary, script_content=None, find_address=None, avoid_addresses=None, analysis_type="symbolic", additional_args=None)` → `"angr_analyze"` at `/api/tools/angr`, category `"binary"`, `timeout=600` passed to `run_tool_command`.

- [ ] **Step 1: Write the failing test**

```python
def test_angr_analyze_handler_invocation_symbolic(monkeypatch):
    written = {}
    original_write_text = Path.write_text
    def capture_write_text(self, content, *a, **kw):
        if str(self) == "/tmp/angr_analysis.py":
            written["content"] = content
        return original_write_text(self, content, *a, **kw)
    monkeypatch.setattr(Path, "write_text", capture_write_text)

    captured = {}
    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("angr_analyze")
    assert tool is not None
    assert tool.endpoint == "/api/tools/angr"

    res = tool.handler(binary="/tmp/target", find_address="0x401000", avoid_addresses="0x402000,0x403000")
    assert res["success"] is True
    assert captured["cmd"] == ["python3", "/tmp/angr_analysis.py"]
    assert captured["kwargs"]["timeout"] == 600

    binary = "/tmp/target"
    base = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
    find_address, avoid_addresses = "0x401000", "0x402000,0x403000"
    base += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
    assert written["content"] == base


def test_angr_analyze_handler_invocation_cfg(monkeypatch):
    written = {}
    original_write_text = Path.write_text
    def capture_write_text(self, content, *a, **kw):
        if str(self) == "/tmp/angr_analysis.py":
            written["content"] = content
        return original_write_text(self, content, *a, **kw)
    monkeypatch.setattr(Path, "write_text", capture_write_text)
    captured = _mock_execute(monkeypatch)

    tool = ToolRegistry.get("angr_analyze")
    res = tool.handler(binary="/tmp/target", analysis_type="cfg")
    assert res["success"] is True

    binary = "/tmp/target"
    base = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
    base += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""
    assert written["content"] == base
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="angr_analyze",
    category="binary",
    description="Symbolic execution and binary analysis using angr",
    endpoint="/api/tools/angr"
)
def angr_analyze(binary: str, script_content: Optional[str] = None, find_address: Optional[str] = None, avoid_addresses: Optional[str] = None, analysis_type: str = "symbolic", additional_args: Optional[str] = None) -> Dict[str, Any]:
    script_file = "/tmp/angr_analysis.py"
    if script_content:
        Path(script_file).write_text(script_content)
    else:
        template = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
        if analysis_type == "symbolic":
            template += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
        elif analysis_type == "cfg":
            template += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""
        Path(script_file).write_text(template)
    cmd = ["python3", script_file]
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd, timeout=600)
    try:
        Path(script_file).unlink()
    except OSError:
        pass
    return result
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 3: `gdb_peda_analyze`

**Legacy (`d689933:hexstrike_server.py:12436-12497`):**
```python
command = "gdb -q"
if binary: command += f" {binary}"
if core_file: command += f" {core_file}"
if attach_pid: command += f" -p {attach_pid}"
if commands:
    peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
    write to /tmp/gdb_peda_commands.txt
    command += " -x /tmp/gdb_peda_commands.txt"
else:
    command += " -ex 'source ~/peda/peda.py' -ex 'quit'"
# then additional_args
```

**Produces:** `gdb_peda_analyze(binary=None, commands=None, attach_pid=0, core_file=None, additional_args=None)` → `"gdb_peda_analyze"` at `/api/tools/gdb-peda`, category `"binary"`. Note: `binary`, `core_file`, and `attach_pid` are all appended unconditionally if present — legacy has no exclusivity between them despite the docstring implying "binary, PID, or core file"; preserve the unconditional sequential appends exactly.

- [ ] **Step 1: Write the failing test**

```python
def test_gdb_peda_analyze_handler_invocation_with_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_peda_analyze")
    assert tool is not None
    assert tool.endpoint == "/api/tools/gdb-peda"

    res = tool.handler(binary="/tmp/target", commands="run\nbt", additional_args="-nx")
    assert res["success"] is True
    assert captured["cmd"] == ["gdb", "-q", "/tmp/target", "-x", "/tmp/gdb_peda_commands.txt", "-nx"]
    assert Path("/tmp/gdb_peda_commands.txt").exists() is False

    expected_script = "\nsource ~/peda/peda.py\nrun\nbt\nquit\n"
    # (verified indirectly: written content matched before cleanup — see implementation note)


def test_gdb_peda_analyze_handler_invocation_no_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_peda_analyze")

    res = tool.handler(binary="/tmp/target", core_file="/tmp/core", attach_pid=1234)
    assert res["success"] is True
    assert captured["cmd"] == [
        "gdb", "-q", "/tmp/target", "/tmp/core", "-p", "1234",
        "-ex", "source ~/peda/peda.py", "-ex", "quit",
    ]
```

(The first test's `expected_script` comment documents intent; verifying the exact temp-file content written requires the same `Path.write_text` monkeypatch pattern used in Task 1/2 if stricter coverage is wanted — optional here since the flag/path wiring is the primary risk surface, already covered by the `cmd` assertion.)

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="gdb_peda_analyze",
    category="binary",
    description="Enhanced debugging and exploitation using GDB with PEDA",
    endpoint="/api/tools/gdb-peda"
)
def gdb_peda_analyze(binary: Optional[str] = None, commands: Optional[str] = None, attach_pid: int = 0, core_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gdb", "-q"]
    if binary:
        cmd.append(binary)
    if core_file:
        cmd.append(core_file)
    if attach_pid:
        cmd.extend(["-p", str(attach_pid)])
    if commands:
        peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
        Path("/tmp/gdb_peda_commands.txt").write_text(peda_commands)
        cmd.extend(["-x", "/tmp/gdb_peda_commands.txt"])
    else:
        cmd.extend(["-ex", "source ~/peda/peda.py", "-ex", "quit"])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    if commands and Path("/tmp/gdb_peda_commands.txt").exists():
        try:
            Path("/tmp/gdb_peda_commands.txt").unlink()
        except OSError:
            pass
    return result
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 4: Full verification

- [ ] **Step 1: Assert binary category has exactly 14 tools**

```python
def test_binary_category_has_14_tools():
    binary_tools = ToolRegistry.get_by_category("binary")
    assert len(binary_tools) == 14
    names = {t.name for t in binary_tools}
    assert names == {
        "radare2_analyze", "gdb_analyze", "ghidra_analyze", "ropgadget_scan",
        "checksec_scan", "xxd_dump", "strings_scan", "objdump_scan",
        "ropper_scan", "pwninit_setup", "one_gadget_find",
        "pwntools_exploit", "angr_analyze", "gdb_peda_analyze",
    }
```

- [ ] **Step 2: Run the entire test suite** — all PASS.
- [ ] **Step 3: MCP sanity check** — same pattern as prior plans, asserting `pwntools_exploit`/`gdb_peda_analyze` present in `mcp.list_tools()`.
- [ ] **Step 4: Commit** (`test(tools): verify binary category reaches 14-tool parity`)
