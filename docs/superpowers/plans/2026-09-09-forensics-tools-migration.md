# Forensics Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port all 6 `forensics`-category tools from the legacy monolith (`hexstrike_server.py` at commit `d689933`) into a new `hexstrike/tools/forensics.py` registry module, creating the `forensics` category from scratch (0 → 6 tools). Unlike the network/web/cloud migrations, this plan covers the category's ENTIRE remaining scope — there is no deferred subset.

**Architecture:** Each tool is a single Python function decorated with `@ToolRegistry.register(...)`, living in a new `hexstrike/tools/forensics.py` file. Each function builds a `List[str]` command (never a shell string) and returns `run_tool_command(cmd)` from `hexstrike/tools/base.py`, following the exact pattern established across `network` (22 tools), `web` (23 tools), and `cloud` (11 tools). `hexstrike/tools/__init__.py` must be updated to import the new module (currently reads `from hexstrike.tools import network, web, binary, password, osint, cloud` — add `forensics` to that list).

**Reused pattern from `cloud`:** `foremost_scan` creates an output directory via `Path(output_dir).mkdir(parents=True, exist_ok=True)` before running, and mutates the `run_tool_command(...)` return dict afterward, adding `result["output_directory"] = output_dir` — identical shape to `cloud`'s `prowler_scan`/`scout_suite_scan`. Preserve exactly.

**New pattern in this plan (not present in network/web/cloud):** `steghide_run` has legacy `action`-based branching (`extract`/`embed`/`info`) that builds three structurally different base commands, and unconditionally appends a `-p` (passphrase) flag with either the real passphrase or an empty string when none is given (legacy: `command += " -p ''"`, a shell-quoted empty argument — the list-form equivalent is simply passing `""` as one argv element, with identical effective behavior since there is no shell to interpret the quotes).

**Tech Stack:** Python 3.13, pytest, `pathlib.Path` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md` (approved architecture this plan extends). Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

## Global Constraints

- **Verbatim behavior**: command construction, flag names, defaults, the directory-creation side effect, and the result-dict mutation must all match the legacy monolith exactly. This plan has no named "dropped feature" exception (unlike `web`'s `nuclei_scan`) — everything is a faithful, unmodified port.
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True` (see `hexstrike/core/process.py:37-43`).
- **`additional_args` handling**: always optional (`Optional[str] = None`), appended via simple `additional_args.split()` (whitespace split — not `shlex.split`).
- **Legacy manual validation is not reproduced for missing required fields**: the old Flask routes did `if not X: return jsonify({"error": ...}), 400`. The new pattern instead makes the field a required parameter with no default; a missing value raises `TypeError`, which `hexstrike/api/app.py:15-20` already converts to a 400 response. Do not re-add manual `if not X` checks for `file_path` (binwalk/exiftool), `input_file` (foremost), `cover_file` (steghide), or `memory_file`/`plugin` (volatility/volatility3) — all become required parameters with no default.
- **`steghide_run`'s action-branching is the one place this plan departs from that rule, and it is intentional — read the Note in Task 4 before implementing it.** Legacy also manually validated that `action` is one of `"extract"/"embed"/"info"` (400 otherwise) and that `embed_file` is present when `action == "embed"` (400 otherwise). Per the same "don't hand-roll manual validation" principle applied everywhere else in this migration, this plan does NOT reproduce either check: implement only the three valid branches as `if/elif/elif` with no trailing `else`, and leave `embed_file` as a plain `Optional[str] = None` used only inside the `embed` branch. An invalid `action` value or a missing `embed_file` on the `embed` path will therefore raise a Python `NameError`/`TypeError` at runtime (caught by `hexstrike/api/app.py`'s generic exception handler as a 500) rather than legacy's specific 400 + message — the same category of behavioral drift on invalid-input paths already accepted throughout this migration (e.g. `arp_scan`, `dalfox_scan`, `zap_scan`, `cloudmapper_run` in the sibling plans), just applied here to an enum-valued field instead of a missing string.
- **Directory-creation and result-mutation side effects preserved literally**: `foremost_scan` calls `Path(output_dir).mkdir(parents=True, exist_ok=True)` before building/running the command (exactly where the legacy route did it), and unconditionally sets `result["output_directory"] = output_dir` after `run_tool_command(cmd)` returns (its `output_dir` parameter has a non-empty default, so legacy never guarded this assignment — do not add an `if output_dir:` guard that wasn't there).
- **`volatility3_scan` uses the `vol.py` binary, not `volatility3`** — legacy: `command = f"vol.py -f {memory_file} {plugin}"`. This is not a typo to "fix"; it is the actual Volatility 3 CLI entry point name.
- **`steghide_run`'s passphrase flag is unconditional**: `-p` is always appended, with the real passphrase when truthy, or an empty string `""` as the argv element when not. Never omit `-p` entirely.
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` (or the equivalent venv in whatever workspace this plan executes in) fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
  ```
  Use this literal text verbatim — do not substitute an implementer's own model identity.

---

### Task 1: Create `hexstrike/tools/forensics.py` and port `binwalk_scan`

**Files:**
- Create: `hexstrike/tools/forensics.py`
- Modify: `hexstrike/tools/__init__.py` (add `forensics` to the import line)
- Test: `tests/test_forensics_tools.py` (create file)

**Interfaces:**
- Consumes: `run_tool_command(cmd: List[str], timeout: int = 300, use_cache: bool = True) -> Dict[str, Any]` from `hexstrike/tools/base.py`; `ToolRegistry.register(...)` decorator and `ToolRegistry.get(name) -> ToolSpec` from `hexstrike/core/registry.py`.
- Produces: `binwalk_scan(file_path, extract=False, additional_args=None)` registered as tool name `"binwalk_scan"` at endpoint `/api/tools/binwalk`, category `"forensics"`.

**Note:** `file_path` is appended LAST, after `additional_args` is processed — preserve that exact order.

- [ ] **Step 1: Write the failing test**

Read the current `hexstrike/tools/__init__.py` first (`cat hexstrike/tools/__init__.py`) to see its exact current import line before editing it in Step 3.

Create `tests/test_forensics_tools.py`:

```python
import pytest
from pathlib import Path
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    """Bypass real binary lookup and subprocess execution, capture the built command."""
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_binwalk_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("binwalk_scan")
    assert tool is not None
    assert tool.category == "forensics"
    assert tool.endpoint == "/api/tools/binwalk"

    res = tool.handler(file_path="/tmp/fw.bin", extract=True, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["binwalk", "-e", "-v", "/tmp/fw.bin"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: FAIL — `ToolRegistry.get("binwalk_scan")` returns `None` (module doesn't exist yet / isn't imported).

- [ ] **Step 3: Write minimal implementation**

Create `hexstrike/tools/forensics.py`:

```python
from pathlib import Path
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="binwalk_scan",
    category="forensics",
    description="Firmware and file analysis using Binwalk",
    endpoint="/api/tools/binwalk"
)
def binwalk_scan(file_path: str, extract: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)
```

Update `hexstrike/tools/__init__.py` to also import `forensics` (edit its existing `from hexstrike.tools import network, web, binary, password, osint, cloud` line to add `forensics` to the list — keep the existing names, just append `forensics`).

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/forensics.py hexstrike/tools/__init__.py tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): create forensics category, port binwalk_scan

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 2: `exiftool_scan`

**Files:**
- Modify: `hexstrike/tools/forensics.py`
- Test: `tests/test_forensics_tools.py`

**Interfaces:**
- Produces: `exiftool_scan(file_path, output_format=None, tags=None, additional_args=None)` registered as `"exiftool_scan"` at `/api/tools/exiftool`.

**Note:** `output_format` and `tags` are turned directly into single-dash flags via string interpolation — `f"-{output_format}"` and `f"-{tags}"` — not via a `-flag value` pair. `file_path` is appended last.

- [ ] **Step 1: Write the failing test**

```python
def test_exiftool_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("exiftool_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/exiftool"

    res = tool.handler(file_path="/tmp/img.jpg", output_format="json", tags="GPS", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["exiftool", "-json", "-GPS", "-v", "/tmp/img.jpg"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py::test_exiftool_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="exiftool_scan",
    category="forensics",
    description="Metadata extraction using ExifTool",
    endpoint="/api/tools/exiftool"
)
def exiftool_scan(file_path: str, output_format: Optional[str] = None, tags: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["exiftool"]
    if output_format:
        cmd.append(f"-{output_format}")
    if tags:
        cmd.append(f"-{tags}")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/forensics.py tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port exiftool_scan to forensics tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 3: `foremost_scan`

**Files:**
- Modify: `hexstrike/tools/forensics.py`
- Test: `tests/test_forensics_tools.py`

**Interfaces:**
- Produces: `foremost_scan(input_file, output_dir="/tmp/foremost_output", file_types=None, additional_args=None)` registered as `"foremost_scan"` at `/api/tools/foremost`.

**Note:** matches the `cloud` category's `prowler_scan`/`scout_suite_scan` pattern: `Path(output_dir).mkdir(parents=True, exist_ok=True)` runs BEFORE command construction, and `result["output_directory"] = output_dir` is set UNCONDITIONALLY after `run_tool_command(cmd)` returns (no `if` guard — `output_dir` has a non-empty default, so legacy never guarded this).

- [ ] **Step 1: Write the failing test**

```python
def test_foremost_scan_handler_invocation(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("foremost_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/foremost"

    output_dir = str(tmp_path / "foremost_output")
    res = tool.handler(input_file="/tmp/disk.img", output_dir=output_dir, file_types="jpg,png", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["foremost", "-o", output_dir, "-t", "jpg,png", "-v", "/tmp/disk.img"]
    assert res["output_directory"] == output_dir
    assert Path(output_dir).is_dir()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py::test_foremost_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="foremost_scan",
    category="forensics",
    description="File carving using Foremost",
    endpoint="/api/tools/foremost"
)
def foremost_scan(input_file: str, output_dir: str = "/tmp/foremost_output", file_types: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["foremost", "-o", output_dir]
    if file_types:
        cmd.extend(["-t", file_types])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(input_file)
    result = run_tool_command(cmd)
    result["output_directory"] = output_dir
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/forensics.py tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port foremost_scan to forensics tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 4: `steghide_run`

**Files:**
- Modify: `hexstrike/tools/forensics.py`
- Test: `tests/test_forensics_tools.py`

**Interfaces:**
- Produces: `steghide_run(cover_file, action="extract", embed_file=None, passphrase=None, output_file=None, additional_args=None)` registered as `"steghide_run"` at `/api/tools/steghide`.

**Note — read this before implementing:** this is the one tool in this plan with action-based branching. Legacy validated `action` is one of `"extract"/"embed"/"info"` and that `embed_file` is present for `"embed"` — per this plan's Global Constraints, do NOT reproduce either check. Implement only three `if/elif/elif` branches (no trailing `else`); an invalid `action` naturally leaves `cmd` unbound (→ `NameError`, caught upstream as a 500) rather than legacy's specific 400. `embed_file` stays a plain `Optional[str] = None`, used only inside the `embed` branch.

The passphrase flag (`-p`) is unconditional: always append it, with the real value if `passphrase` is truthy, else an empty string `""` as the argv element (equivalent to legacy's shell-quoted `-p ''`).

- [ ] **Step 1: Write the failing test**

```python
def test_steghide_run_handler_invocation_extract(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("steghide_run")
    assert tool is not None
    assert tool.endpoint == "/api/tools/steghide"

    res = tool.handler(cover_file="/tmp/img.jpg", action="extract", output_file="/tmp/out.txt", passphrase="secret", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["steghide", "extract", "-sf", "/tmp/img.jpg", "-xf", "/tmp/out.txt", "-p", "secret", "-v"]


def test_steghide_run_handler_invocation_embed_no_passphrase(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("steghide_run")

    res = tool.handler(cover_file="/tmp/img.jpg", action="embed", embed_file="/tmp/secret.txt")
    assert res["success"] is True
    assert captured["cmd"] == ["steghide", "embed", "-cf", "/tmp/img.jpg", "-ef", "/tmp/secret.txt", "-p", ""]


def test_steghide_run_handler_invocation_info(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("steghide_run")

    res = tool.handler(cover_file="/tmp/img.jpg", action="info", passphrase="pw")
    assert res["success"] is True
    assert captured["cmd"] == ["steghide", "info", "/tmp/img.jpg", "-p", "pw"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -k steghide -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="steghide_run",
    category="forensics",
    description="Steganography analysis using Steghide",
    endpoint="/api/tools/steghide"
)
def steghide_run(cover_file: str, action: str = "extract", embed_file: Optional[str] = None, passphrase: Optional[str] = None, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    if action == "extract":
        cmd = ["steghide", "extract", "-sf", cover_file]
        if output_file:
            cmd.extend(["-xf", output_file])
    elif action == "embed":
        cmd = ["steghide", "embed", "-cf", cover_file, "-ef", embed_file]
    elif action == "info":
        cmd = ["steghide", "info", cover_file]
    if passphrase:
        cmd.extend(["-p", passphrase])
    else:
        cmd.extend(["-p", ""])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/forensics.py tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port steghide_run to forensics tool registry

Implements only the three valid action branches (extract/embed/info)
per this plan's global constraint against hand-rolled validation —
an invalid action or a missing embed_file on the embed path raises
naturally (NameError/TypeError -> 500) rather than reproducing
legacy's specific 400 responses, consistent with how every other
required-field check is handled throughout this migration.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 5: `volatility_scan`

**Files:**
- Modify: `hexstrike/tools/forensics.py`
- Test: `tests/test_forensics_tools.py`

**Interfaces:**
- Produces: `volatility_scan(memory_file, plugin, profile=None, additional_args=None)` registered as `"volatility_scan"` at `/api/tools/volatility`.

**Note:** both `memory_file` and `plugin` are required (no default) — this tool has two required fields, matching legacy's two separate manual validations, both dropped per Global Constraints. `plugin` is appended AFTER the optional `--profile=` flag, and `additional_args` comes last, after `plugin`.

- [ ] **Step 1: Write the failing test**

```python
def test_volatility_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("volatility_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/volatility"

    res = tool.handler(memory_file="/tmp/mem.dmp", plugin="pslist", profile="Win10x64", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["volatility", "-f", "/tmp/mem.dmp", "--profile=Win10x64", "pslist", "-v"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py::test_volatility_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="volatility_scan",
    category="forensics",
    description="Memory forensics using Volatility",
    endpoint="/api/tools/volatility"
)
def volatility_scan(memory_file: str, plugin: str, profile: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["volatility", "-f", memory_file]
    if profile:
        cmd.append(f"--profile={profile}")
    cmd.append(plugin)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/forensics.py tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port volatility_scan to forensics tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 6: `volatility3_scan`

**Files:**
- Modify: `hexstrike/tools/forensics.py`
- Test: `tests/test_forensics_tools.py`

**Interfaces:**
- Produces: `volatility3_scan(memory_file, plugin, output_file=None, additional_args=None)` registered as `"volatility3_scan"` at `/api/tools/volatility3`.

**Note:** legacy invokes the `vol.py` binary (Volatility 3's actual CLI entry point name), NOT `volatility3` — do not "correct" this. `plugin` is a required positional argument placed directly in the base command list (`["vol.py", "-f", memory_file, plugin]`), unlike `volatility_scan` (Task 5) where `plugin` is appended after the optional `--profile=` flag.

- [ ] **Step 1: Write the failing test**

```python
def test_volatility3_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("volatility3_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/volatility3"

    res = tool.handler(memory_file="/tmp/mem.dmp", plugin="windows.pslist", output_file="/tmp/out.txt", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["vol.py", "-f", "/tmp/mem.dmp", "windows.pslist", "-o", "/tmp/out.txt", "-v"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py::test_volatility3_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="volatility3_scan",
    category="forensics",
    description="Advanced memory forensics using Volatility 3",
    endpoint="/api/tools/volatility3"
)
def volatility3_scan(memory_file: str, plugin: str, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["vol.py", "-f", memory_file, plugin]
    if output_file:
        cmd.extend(["-o", output_file])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_forensics_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/forensics.py tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port volatility3_scan to forensics tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 7: Full verification

**Files:** none created/modified beyond one test addition.

**Interfaces:**
- Consumes: `ToolRegistry.get_by_category("forensics")` from `hexstrike/core/registry.py`.

- [ ] **Step 1: Assert forensics category has exactly 6 tools**

Add to `tests/test_forensics_tools.py`:

```python
def test_forensics_category_has_6_tools():
    from hexstrike.core.registry import ToolRegistry
    import hexstrike.tools
    forensics_tools = ToolRegistry.get_by_category("forensics")
    assert len(forensics_tools) == 6
    names = {t.name for t in forensics_tools}
    assert names == {
        "binwalk_scan", "exiftool_scan", "foremost_scan",
        "steghide_run", "volatility_scan", "volatility3_scan",
    }
```

- [ ] **Step 2: Run the entire test suite**

Run: `./.venv/bin/python3 -m pytest tests/ -v`
Expected: all tests PASS.

- [ ] **Step 3: Sanity-check the MCP layer picks up the new tools**

Run:
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
    assert 'binwalk_scan' in names
    assert 'volatility3_scan' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```
Expected: no assertion error. Note the printed count depends on which other category branches have already been merged into whatever base this plan executes against — this task should NOT assert a specific total number, only that the two named forensics tools are present (see the `web`/`cloud` migrations' retrospective note about a similar count assumption going stale when sibling branches merge out of order).

- [ ] **Step 4: Commit**

```bash
git add tests/test_forensics_tools.py
git commit -m "$(cat <<'EOF'
test(tools): verify forensics category reaches full 6-tool parity

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```
