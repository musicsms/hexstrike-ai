# Binary Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port 10 mechanical CLI-wrapper `binary`-category tools from the legacy monolith (`hexstrike_server.py` at commit `d689933`) into the modular `hexstrike/tools/binary.py` registry, extending the category from 1 tool (`radare2_analyze`) to 11: `gdb_analyze`, `ghidra_analyze`, `ropgadget_scan`, `checksec_scan`, `xxd_dump`, `strings_scan`, `objdump_scan`, `ropper_scan`, `pwninit_setup`, `one_gadget_find`.

**Architecture:** Same pattern as `network`/`web`/`cloud`/`forensics`/`password`/`osint`: each tool is a single Python function decorated with `@ToolRegistry.register(...)`, building a `List[str]` command and returning `run_tool_command(cmd)` from `hexstrike/tools/base.py`. `hexstrike/tools/__init__.py` already imports `binary` (no change needed there).

**Tech Stack:** Python 3.13, pytest, `pathlib.Path` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`. Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

**Explicit scope boundary:** the `binary` category in the legacy monolith has 16 tools total (`radare2` and `binwalk` already ported — `binwalk` landed under the `forensics` category, not `binary`, per that migration's design choice). Of the 14 remaining, this plan covers only the 10 that are simple CLI wrappers matching the established mechanical pattern. The other 4 are explicitly OUT of scope for this plan and must NOT be added to `hexstrike/tools/binary.py` here — they need separate design work first:
- `pwntools`, `angr` — legacy writes a full Python script (either user-supplied `script_content` or a generated exploit/analysis template embedding target parameters) to a fixed temp file, then runs `python3 {temp_file}`, then deletes it. Porting this faithfully means deciding how much of the multi-branch template-generation logic (the `analysis_type`-driven angr template, the `exploit_type`-driven pwntools template) is in scope for a "tool wrapper" versus being considered code generation — a design decision, not a mechanical port.
- `gdb-peda` — legacy branches on whether `commands` is supplied: with it, writes a multi-line PEDA init script (`source ~/peda/peda.py` + user commands + `quit`) to a temp file and runs `gdb -x {temp_file}`; without it, falls back to two separate `-ex` flags. Also accepts three mutually-exclusive-ish target kinds (`binary`, `core_file`, `attach_pid`) all appended unconditionally if present, which needs a decision on argument ordering/precedence not present in the simpler tools in this plan.
- `libc-database` — legacy is a genuine shell pipeline: `cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo '...' && ./{action} {args}`, relying on shell `cd`/`||`/`&&`/stderr-redirect semantics with no `List[str]` equivalent as written. A faithful port needs a `cwd=`-based directory-resolution helper decided as its own small design, not copied mechanically like the tools in this plan.

## Global Constraints

- **Verbatim behavior**: command construction, flag names, defaults, and the two directory/temp-file side effects in this plan (`gdb_analyze`'s command-script write+cleanup, `ghidra_analyze`'s project-directory creation) must match the legacy monolith exactly.
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True` (see `hexstrike/core/process.py:37-43`). A legacy single-quoted shell argument (e.g. `--search '{x}'`, `--only '{x}'`) becomes one list element holding the raw value — no manual quoting needed, since there is no shell to escape for.
- **`additional_args` handling**: always optional (`Optional[str] = None`), appended via `additional_args.split()` (whitespace split — not `shlex.split`).
- **Legacy manual validation is not reproduced for missing required fields**: the old Flask routes did `if not X: return jsonify({"error": ...}), 400`. The new pattern makes the field a required parameter with no default; a missing value raises `TypeError`, converted to a 400 by `hexstrike/api/app.py:15-20`. Do not re-add manual `if not X` checks for `binary`/`file_path`/`libc_path` across every task in this plan.
- **`gdb_analyze`'s temp-file side effect preserved literally**: when `commands` is supplied, legacy writes it verbatim to `/tmp/gdb_commands.txt`, appends `-x /tmp/gdb_commands.txt` to the command, and — after execution — deletes that file if it exists, swallowing any deletion error (legacy uses a bare `except: pass`). Preserve this exact temp-file path and swallow-on-cleanup-failure behavior.
- **`ghidra_analyze`'s directory-creation side effect preserved literally**: `os.makedirs(f"/tmp/ghidra_projects/{project_name}", exist_ok=True)` runs before command construction, matching the `foremost_scan`/`prowler_scan` precedent (`Path(...).mkdir(parents=True, exist_ok=True)` is the modern equivalent already used elsewhere in this codebase — semantically identical to `os.makedirs(..., exist_ok=True)`).
- **`one_gadget_find`'s argument order is positional-then-flag** (`one_gadget {libc_path} --level {level}`), the reverse of most other tools in this plan (which put `--binary`/`--file` flags first, target path last, or no separate flag at all).
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UCXzPVYGQRPh8iwyajTsRt
  ```

---

### Task 1: `gdb_analyze`

**Legacy (`d689933:hexstrike_server.py:11960-12004`):**
```python
command = f"gdb {binary}"
if script_file:
    command += f" -x {script_file}"
if commands:
    with open("/tmp/gdb_commands.txt", "w") as f:
        f.write(commands)
    command += f" -x /tmp/gdb_commands.txt"
if additional_args:
    command += f" {additional_args}"
command += " -batch"
# ...execute...
if commands and os.path.exists("/tmp/gdb_commands.txt"):
    try:
        os.remove("/tmp/gdb_commands.txt")
    except:
        pass
```

**Produces:** `gdb_analyze(binary, commands=None, script_file=None, additional_args=None)` → `"gdb_analyze"` at `/api/tools/gdb`, category `"binary"`.

- [ ] **Step 1: Write the failing test**

```python
import pytest
from pathlib import Path
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_gdb_analyze_handler_invocation_with_commands(monkeypatch, tmp_path, monkeypatch_cwd=None):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_analyze")
    assert tool is not None
    assert tool.category == "binary"
    assert tool.endpoint == "/api/tools/gdb"

    res = tool.handler(binary="/tmp/target", commands="run\nbt", additional_args="-nx")
    assert res["success"] is True
    assert captured["cmd"] == ["gdb", "/tmp/target", "-x", "/tmp/gdb_commands.txt", "-nx", "-batch"]
    assert Path("/tmp/gdb_commands.txt").exists() is False  # cleaned up after execution
```

Note: since the temp file is written and then deleted by the handler itself around the mocked `execute_command` call, assert the file is gone *after* `tool.handler(...)` returns — the test above already does this correctly (the `open`/`write`/`remove` calls are real filesystem operations in `/tmp`, only the subprocess call is mocked).

Add a second case:
```python
def test_gdb_analyze_handler_invocation_no_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_analyze")

    res = tool.handler(binary="/tmp/target", script_file="/tmp/script.gdb")
    assert res["success"] is True
    assert captured["cmd"] == ["gdb", "/tmp/target", "-x", "/tmp/script.gdb", "-batch"]
```

- [ ] **Step 2: Run test to verify it fails** — `ToolRegistry.get("gdb_analyze")` returns `None`.

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="gdb_analyze",
    category="binary",
    description="Binary analysis and debugging using GDB",
    endpoint="/api/tools/gdb"
)
def gdb_analyze(binary: str, commands: Optional[str] = None, script_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gdb", binary]
    if script_file:
        cmd.extend(["-x", script_file])
    if commands:
        Path("/tmp/gdb_commands.txt").write_text(commands)
        cmd.extend(["-x", "/tmp/gdb_commands.txt"])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append("-batch")
    result = run_tool_command(cmd)
    if commands and Path("/tmp/gdb_commands.txt").exists():
        try:
            Path("/tmp/gdb_commands.txt").unlink()
        except OSError:
            pass
    return result
```

(`hexstrike/tools/binary.py` will need `from pathlib import Path` added to its imports if not already present.)

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit** (`git add hexstrike/tools/binary.py tests/test_binary_tools.py`, message `feat(tools): port gdb_analyze to binary tool registry`)

---

### Task 2: `ghidra_analyze`

**Legacy (`d689933:hexstrike_server.py:12251-12280`):**
```python
project_dir = f"/tmp/ghidra_projects/{project_name}"
os.makedirs(project_dir, exist_ok=True)
command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"
if script_file:
    command += f" -postScript {script_file}"
if output_format == "xml":
    command += f" -postScript ExportXml.java {project_dir}/analysis.xml"
if additional_args:
    command += f" {additional_args}"
# execute with timeout=analysis_timeout
```

**Produces:** `ghidra_analyze(binary, project_name="hexstrike_analysis", script_file=None, analysis_timeout=300, output_format="xml", additional_args=None)` → `"ghidra_analyze"` at `/api/tools/ghidra`, category `"binary"`. Note: `analysis_timeout` is passed through to `run_tool_command(cmd, timeout=analysis_timeout)` — check `run_tool_command`'s signature in `hexstrike/tools/base.py` accepts a `timeout` kwarg (it does, per the forensics/cloud plans' Interfaces sections: `run_tool_command(cmd, timeout=300, use_cache=True)`).

- [ ] **Step 1: Write the failing test**

```python
def test_ghidra_analyze_handler_invocation(monkeypatch, tmp_path):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("ghidra_analyze")
    assert tool is not None
    assert tool.endpoint == "/api/tools/ghidra"

    res = tool.handler(binary="/tmp/target", project_name="proj1", analysis_timeout=120, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == [
        "analyzeHeadless", "/tmp/ghidra_projects/proj1", "proj1",
        "-import", "/tmp/target", "-deleteProject",
        "-postScript", "ExportXml.java", "/tmp/ghidra_projects/proj1/analysis.xml",
        "-v",
    ]
    assert Path("/tmp/ghidra_projects/proj1").is_dir()
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="ghidra_analyze",
    category="binary",
    description="Advanced binary analysis and reverse engineering using Ghidra",
    endpoint="/api/tools/ghidra"
)
def ghidra_analyze(binary: str, project_name: str = "hexstrike_analysis", script_file: Optional[str] = None, analysis_timeout: int = 300, output_format: str = "xml", additional_args: Optional[str] = None) -> Dict[str, Any]:
    project_dir = f"/tmp/ghidra_projects/{project_name}"
    Path(project_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["analyzeHeadless", project_dir, project_name, "-import", binary, "-deleteProject"]
    if script_file:
        cmd.extend(["-postScript", script_file])
    if output_format == "xml":
        cmd.extend(["-postScript", "ExportXml.java", f"{project_dir}/analysis.xml"])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=analysis_timeout)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 3: `ropgadget_scan`

**Legacy (`d689933:hexstrike_server.py:12087-12105`):** `command = f"ROPgadget --binary {binary}"`; if `gadget_type`: `command += f" --only '{gadget_type}'"`; then `additional_args`.

**Produces:** `ropgadget_scan(binary, gadget_type=None, additional_args=None)` → `"ropgadget_scan"` at `/api/tools/ropgadget`.

- [ ] **Step 1: Write the failing test**

```python
def test_ropgadget_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("ropgadget_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/ropgadget"

    res = tool.handler(binary="/tmp/target", gadget_type="pop", additional_args="--depth 5")
    assert res["success"] is True
    assert captured["cmd"] == ["ROPgadget", "--binary", "/tmp/target", "--only", "pop", "--depth", "5"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="ropgadget_scan",
    category="binary",
    description="ROP gadget search using ROPgadget",
    endpoint="/api/tools/ropgadget"
)
def ropgadget_scan(binary: str, gadget_type: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["ROPgadget", "--binary", binary]
    if gadget_type:
        cmd.extend(["--only", gadget_type])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 4: `checksec_scan`

**Legacy (`d689933:hexstrike_server.py:12120-12134`):** `command = f"checksec --file={binary}"` — no `additional_args`, no other params.

**Produces:** `checksec_scan(binary)` → `"checksec_scan"` at `/api/tools/checksec`.

- [ ] **Step 1: Write the failing test**

```python
def test_checksec_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("checksec_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/checksec"

    res = tool.handler(binary="/tmp/target")
    assert res["success"] is True
    assert captured["cmd"] == ["checksec", "--file=/tmp/target"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="checksec_scan",
    category="binary",
    description="Binary security feature check using Checksec",
    endpoint="/api/tools/checksec"
)
def checksec_scan(binary: str) -> Dict[str, Any]:
    cmd = [f"checksec", f"--file={binary}"]
    return run_tool_command(cmd)
```

Note: `checksec` is a single fixed string in the list (`"checksec"`), then `f"--file={binary}"` as its own element — write it as `cmd = ["checksec", f"--file={binary}"]` (no need for the redundant f-string on the first element).

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 5: `xxd_dump`

**Legacy (`d689933:hexstrike_server.py:12145-12167`):** `command = f"xxd -s {offset}"`; if `length`: `command += f" -l {length}"`; then `additional_args`; then `command += f" {file_path}"` (file path LAST).

**Produces:** `xxd_dump(file_path, offset="0", length=None, additional_args=None)` → `"xxd_dump"` at `/api/tools/xxd`.

- [ ] **Step 1: Write the failing test**

```python
def test_xxd_dump_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("xxd_dump")
    assert tool is not None
    assert tool.endpoint == "/api/tools/xxd"

    res = tool.handler(file_path="/tmp/f.bin", offset="16", length="64", additional_args="-c 8")
    assert res["success"] is True
    assert captured["cmd"] == ["xxd", "-s", "16", "-l", "64", "-c", "8", "/tmp/f.bin"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="xxd_dump",
    category="binary",
    description="Hex dump generation using xxd",
    endpoint="/api/tools/xxd"
)
def xxd_dump(file_path: str, offset: str = "0", length: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["xxd", "-s", offset]
    if length:
        cmd.extend(["-l", length])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 6: `strings_scan`

**Legacy (`d689933:hexstrike_server.py:12181-12200`):** `command = f"strings -n {min_len}"`; then `additional_args`; then `command += f" {file_path}"` (file path LAST).

**Produces:** `strings_scan(file_path, min_len=4, additional_args=None)` → `"strings_scan"` at `/api/tools/strings`.

- [ ] **Step 1: Write the failing test**

```python
def test_strings_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("strings_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/strings"

    res = tool.handler(file_path="/tmp/f.bin", min_len=8, additional_args="-a")
    assert res["success"] is True
    assert captured["cmd"] == ["strings", "-n", "8", "-a", "/tmp/f.bin"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="strings_scan",
    category="binary",
    description="String extraction from binary files using strings",
    endpoint="/api/tools/strings"
)
def strings_scan(file_path: str, min_len: int = 4, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["strings", "-n", str(min_len)]
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 7: `objdump_scan`

**Legacy (`d689933:hexstrike_server.py:12213-12234`):** `command = "objdump"`; if `disassemble` (default `True`): `command += " -d"` else `" -x"`; then `additional_args`; then `command += f" {binary}"` (binary LAST).

**Produces:** `objdump_scan(binary, disassemble=True, additional_args=None)` → `"objdump_scan"` at `/api/tools/objdump`.

- [ ] **Step 1: Write the failing test**

```python
def test_objdump_scan_handler_invocation_disassemble(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("objdump_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/objdump"

    res = tool.handler(binary="/tmp/target", additional_args="-C")
    assert res["success"] is True
    assert captured["cmd"] == ["objdump", "-d", "-C", "/tmp/target"]


def test_objdump_scan_handler_invocation_headers(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("objdump_scan")

    res = tool.handler(binary="/tmp/target", disassemble=False)
    assert res["success"] is True
    assert captured["cmd"] == ["objdump", "-x", "/tmp/target"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="objdump_scan",
    category="binary",
    description="Binary analysis using objdump",
    endpoint="/api/tools/objdump"
)
def objdump_scan(binary: str, disassemble: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["objdump"]
    if disassemble:
        cmd.append("-d")
    else:
        cmd.append("-x")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(binary)
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 8: `ropper_scan`

**Legacy (`d689933:hexstrike_server.py:12589-12621`):**
```python
command = f"ropper --file {binary}"
if gadget_type == "rop": command += " --rop"
elif gadget_type == "jop": command += " --jop"
elif gadget_type == "sys": command += " --sys"
elif gadget_type == "all": command += " --all"
if quality > 1: command += f" --quality {quality}"
if arch: command += f" --arch {arch}"
if search_string: command += f" --search '{search_string}'"
# then additional_args
```

**Produces:** `ropper_scan(binary, gadget_type="rop", quality=1, arch=None, search_string=None, additional_args=None)` → `"ropper_scan"` at `/api/tools/ropper`.

- [ ] **Step 1: Write the failing test**

```python
def test_ropper_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("ropper_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/ropper"

    res = tool.handler(binary="/tmp/target", gadget_type="jop", quality=3, arch="x86_64", search_string="pop rdi", additional_args="--nocolor")
    assert res["success"] is True
    assert captured["cmd"] == [
        "ropper", "--file", "/tmp/target", "--jop",
        "--quality", "3", "--arch", "x86_64", "--search", "pop rdi", "--nocolor",
    ]


def test_ropper_scan_handler_invocation_defaults(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("ropper_scan")

    res = tool.handler(binary="/tmp/target")
    assert res["success"] is True
    assert captured["cmd"] == ["ropper", "--file", "/tmp/target", "--rop"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="ropper_scan",
    category="binary",
    description="Advanced ROP/JOP gadget search using ropper",
    endpoint="/api/tools/ropper"
)
def ropper_scan(binary: str, gadget_type: str = "rop", quality: int = 1, arch: Optional[str] = None, search_string: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["ropper", "--file", binary]
    if gadget_type == "rop":
        cmd.append("--rop")
    elif gadget_type == "jop":
        cmd.append("--jop")
    elif gadget_type == "sys":
        cmd.append("--sys")
    elif gadget_type == "all":
        cmd.append("--all")
    if quality > 1:
        cmd.extend(["--quality", str(quality)])
    if arch:
        cmd.extend(["--arch", arch])
    if search_string:
        cmd.extend(["--search", search_string])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 9: `pwninit_setup`

**Legacy (`d689933:hexstrike_server.py:12636-12658`):**
```python
command = f"pwninit --bin {binary}"
if libc: command += f" --libc {libc}"
if ld: command += f" --ld {ld}"
if template_type: command += f" --template {template_type}"
# then additional_args
```

**Produces:** `pwninit_setup(binary, libc=None, ld=None, template_type="python", additional_args=None)` → `"pwninit_setup"` at `/api/tools/pwninit`. Note: `template_type` defaults to `"python"` (truthy), so its flag is emitted unconditionally under default usage — preserve the `if template_type:` check as-is rather than assuming it's always present (a caller could still pass `None`).

- [ ] **Step 1: Write the failing test**

```python
def test_pwninit_setup_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwninit_setup")
    assert tool is not None
    assert tool.endpoint == "/api/tools/pwninit"

    res = tool.handler(binary="/tmp/target", libc="/tmp/libc.so.6", ld="/tmp/ld.so", additional_args="--force")
    assert res["success"] is True
    assert captured["cmd"] == [
        "pwninit", "--bin", "/tmp/target", "--libc", "/tmp/libc.so.6",
        "--ld", "/tmp/ld.so", "--template", "python", "--force",
    ]


def test_pwninit_setup_handler_invocation_no_template(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwninit_setup")

    res = tool.handler(binary="/tmp/target", template_type=None)
    assert res["success"] is True
    assert captured["cmd"] == ["pwninit", "--bin", "/tmp/target"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="pwninit_setup",
    category="binary",
    description="CTF binary exploitation setup using pwninit",
    endpoint="/api/tools/pwninit"
)
def pwninit_setup(binary: str, libc: Optional[str] = None, ld: Optional[str] = None, template_type: Optional[str] = "python", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["pwninit", "--bin", binary]
    if libc:
        cmd.extend(["--libc", libc])
    if ld:
        cmd.extend(["--ld", ld])
    if template_type:
        cmd.extend(["--template", template_type])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 10: `one_gadget_find`

**Legacy (`d689933:hexstrike_server.py:12369-12384`):** `command = f"one_gadget {libc_path} --level {level}"` — positional path FIRST, then `--level`, then `additional_args`.

**Produces:** `one_gadget_find(libc_path, level=1, additional_args=None)` → `"one_gadget_find"` at `/api/tools/one-gadget`.

- [ ] **Step 1: Write the failing test**

```python
def test_one_gadget_find_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("one_gadget_find")
    assert tool is not None
    assert tool.endpoint == "/api/tools/one-gadget"

    res = tool.handler(libc_path="/tmp/libc.so.6", level=2, additional_args="--raw")
    assert res["success"] is True
    assert captured["cmd"] == ["one_gadget", "/tmp/libc.so.6", "--level", "2", "--raw"]
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="one_gadget_find",
    category="binary",
    description="One-shot RCE gadget search in libc using one_gadget",
    endpoint="/api/tools/one-gadget"
)
def one_gadget_find(libc_path: str, level: int = 1, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["one_gadget", libc_path, "--level", str(level)]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 11: Full verification

- [ ] **Step 1: Assert binary category has exactly 11 tools**

```python
def test_binary_category_has_11_tools():
    binary_tools = ToolRegistry.get_by_category("binary")
    assert len(binary_tools) == 11
    names = {t.name for t in binary_tools}
    assert names == {
        "radare2_analyze", "gdb_analyze", "ghidra_analyze", "ropgadget_scan",
        "checksec_scan", "xxd_dump", "strings_scan", "objdump_scan",
        "ropper_scan", "pwninit_setup", "one_gadget_find",
    }
```

- [ ] **Step 2: Run the entire test suite** — `./.venv/bin/python3 -m pytest tests/ -v` — all PASS.

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
    assert 'gdb_analyze' in names
    assert 'one_gadget_find' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```

- [ ] **Step 4: Commit** (`test(tools): verify binary category reaches 11-tool parity for the mechanical subset`)
