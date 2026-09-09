# Cloud Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port 11 of the 12 `cloud`-category tools from the legacy monolith (`hexstrike_server.py` at commit `d689933`) into a new `hexstrike/tools/cloud.py` registry module, creating the `cloud` category from scratch (0 → 11 tools).

**Architecture:** Each tool is a single Python function decorated with `@ToolRegistry.register(...)`, living in a new `hexstrike/tools/cloud.py` file. Each function builds a `List[str]` command (never a shell string) and returns `run_tool_command(cmd)` from `hexstrike/tools/base.py`, following the exact pattern established across the `network` (22 tools, see `docs/superpowers/plans/2026-09-09-network-tools-migration.md`) and `web` (20 tools, see `docs/superpowers/plans/2026-09-09-web-tools-migration.md`) category migrations. `hexstrike/tools/__init__.py` must be updated to import the new module so its `@ToolRegistry.register` decorators run at startup, matching how `network`/`web`/etc. are already wired in.

**New pattern in this plan (not present in network/web):** four of these tools do more than build-and-run a command — three (`prowler_scan`, `scout_suite_scan`) create an output directory via `Path(...).mkdir(parents=True, exist_ok=True)` *before* running, and four (`prowler_scan`, `trivy_scan`, `scout_suite_scan`, `docker_bench_security_scan`) mutate the `run_tool_command(...)` return dict afterward, adding a field like `output_directory`/`output_file`/`report_directory` that echoes a parameter back to the caller. Preserve both behaviors exactly — this is legacy behavior, not something to simplify away.

**Tech Stack:** Python 3.13, pytest, `pathlib.Path` (new import for this file) — no other new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md` (approved architecture this plan extends). Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

**Explicit scope boundary:** the `cloud` category in the legacy monolith has 12 tools total, not 11. `pacu` is explicitly OUT of scope for this plan and must NOT be added to `hexstrike/tools/cloud.py` here:
- `pacu` — legacy builds a multi-line command script, writes it to a temp file (`/tmp/pacu_commands.txt`), and runs `pacu < {command_file}` (shell stdin redirect from a file), then deletes the temp file. This needs the same `ProcessManager` stdin-input capability already identified as missing when `anew`/`qsreplace`/`uro`/`hakrawler` were deferred out of the web-tools-migration plan — port it alongside those four in that future stdin-support sub-project, not here.

## Global Constraints

- **Verbatim behavior**: command construction, flag names, default values, directory-creation side effects, and result-dict mutations must all match the legacy monolith exactly, with no undocumented deviations in this plan.
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True` (see `hexstrike/core/process.py:37-43`).
- **`additional_args` handling**: always optional (`Optional[str] = None`), appended via simple `additional_args.split()` (whitespace split, matching the network/web-category convention — not `shlex.split`).
- **Legacy manual validation is not reproduced**: the old Flask routes did `if not X: return jsonify({"error": ...}), 400`. The new pattern instead makes the field a required parameter with no default; a missing value raises `TypeError`, which `hexstrike/api/app.py:15-20` already converts to a 400 response. Do not re-add manual `if not X` checks. One tool (`cloudmapper_run`) has a legacy either-or requirement (`account` OR `action == "webserver"`) — per the established precedent (`arp_scan` in the network plan), leave `account` `Optional` and do not hand-roll the either-or validation.
- **Directory-creation side effects are preserved literally**: `prowler_scan` and `scout_suite_scan` call `Path(output_dir).mkdir(parents=True, exist_ok=True)` / `Path(report_dir).mkdir(parents=True, exist_ok=True)` *before* building/running the command, exactly where the legacy route did it (immediately after reading params, before command construction).
- **Result-dict field mutation is preserved literally**: `prowler_scan` adds `result["output_directory"]`, `trivy_scan` conditionally adds `result["output_file"]` (only if `output_file` was given), `scout_suite_scan` adds `result["report_directory"]`, and `docker_bench_security_scan` *unconditionally* adds `result["output_file"]` (its `output_file` parameter has a non-empty default, so the legacy code never actually guarded this assignment — preserve that; do not add an `if output_file:` guard around it that the legacy code didn't have).
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` (or the equivalent venv in whatever workspace this plan executes in) fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
  ```
  Use this literal text verbatim — do not substitute an implementer's own model identity.

---

### Task 1: Create `hexstrike/tools/cloud.py` and port `prowler_scan`

**Files:**
- Create: `hexstrike/tools/cloud.py`
- Modify: `hexstrike/tools/__init__.py` (add `cloud` to the import line)
- Test: `tests/test_cloud_tools.py` (create file)

**Interfaces:**
- Consumes: `run_tool_command(cmd: List[str], timeout: int = 300, use_cache: bool = True) -> Dict[str, Any]` from `hexstrike/tools/base.py`; `ToolRegistry.register(...)` decorator and `ToolRegistry.get(name) -> ToolSpec` from `hexstrike/core/registry.py`.
- Produces: `prowler_scan(provider="aws", profile="default", region=None, checks=None, output_dir="/tmp/prowler_output", output_format="json", additional_args=None)` registered as tool name `"prowler_scan"` at endpoint `/api/tools/prowler`, category `"cloud"`.

- [ ] **Step 1: Write the failing test**

Read the current `hexstrike/tools/__init__.py` first (`cat hexstrike/tools/__init__.py`) to see its exact current import line before editing it in Step 3.

Create `tests/test_cloud_tools.py`:

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


def test_prowler_scan_handler_invocation(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("prowler_scan")
    assert tool is not None
    assert tool.category == "cloud"
    assert tool.endpoint == "/api/tools/prowler"

    output_dir = str(tmp_path / "prowler_output")
    res = tool.handler(
        provider="aws", profile="myprofile", region="us-east-1", checks="check1,check2",
        output_dir=output_dir, output_format="json", additional_args="-M csv",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "prowler", "aws",
        "--profile", "myprofile",
        "--region", "us-east-1",
        "--checks", "check1,check2",
        "--output-directory", output_dir,
        "--output-format", "json",
        "-M", "csv",
    ]
    assert res["output_directory"] == output_dir
    assert Path(output_dir).is_dir()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: FAIL — `ToolRegistry.get("prowler_scan")` returns `None` (module doesn't exist yet / isn't imported).

- [ ] **Step 3: Write minimal implementation**

Create `hexstrike/tools/cloud.py`:

```python
from pathlib import Path
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="prowler_scan",
    category="cloud",
    description="AWS/multi-cloud security assessment using Prowler",
    endpoint="/api/tools/prowler"
)
def prowler_scan(provider: str = "aws", profile: Optional[str] = "default", region: Optional[str] = None, checks: Optional[str] = None, output_dir: str = "/tmp/prowler_output", output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["prowler", provider]
    if profile:
        cmd.extend(["--profile", profile])
    if region:
        cmd.extend(["--region", region])
    if checks:
        cmd.extend(["--checks", checks])
    cmd.extend(["--output-directory", output_dir])
    cmd.extend(["--output-format", output_format])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    result["output_directory"] = output_dir
    return result
```

Update `hexstrike/tools/__init__.py` to also import `cloud` (edit its existing `from hexstrike.tools import network, web, binary, password, osint` line to add `cloud` to the list — keep the existing names, just add `cloud`).

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py hexstrike/tools/__init__.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): create cloud category, port prowler_scan

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 2: `trivy_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `trivy_scan(target, scan_type="image", output_format="json", severity=None, output_file=None, additional_args=None)` registered as `"trivy_scan"` at `/api/tools/trivy`.

**Note:** `result["output_file"]` is only added when `output_file` is truthy (it defaults to `None`) — this is a conditional mutation, unlike `docker_bench_security_scan`'s unconditional one in Task 7.

- [ ] **Step 1: Write the failing test**

```python
def test_trivy_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("trivy_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/trivy"

    res = tool.handler(
        target="myimage:latest", scan_type="image", output_format="json",
        severity="HIGH,CRITICAL", output_file="/tmp/out.json", additional_args="--timeout 5m",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "trivy", "image", "myimage:latest",
        "--format", "json", "--severity", "HIGH,CRITICAL", "--output", "/tmp/out.json",
        "--timeout", "5m",
    ]
    assert res["output_file"] == "/tmp/out.json"

    res2 = tool.handler(target="myimage:latest")
    assert "output_file" not in res2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_trivy_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="trivy_scan",
    category="cloud",
    description="Container/filesystem vulnerability scanning using Trivy",
    endpoint="/api/tools/trivy"
)
def trivy_scan(target: str, scan_type: str = "image", output_format: str = "json", severity: Optional[str] = None, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["trivy", scan_type, target]
    if output_format:
        cmd.extend(["--format", output_format])
    if severity:
        cmd.extend(["--severity", severity])
    if output_file:
        cmd.extend(["--output", output_file])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    if output_file:
        result["output_file"] = output_file
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port trivy_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 3: `scout_suite_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `scout_suite_scan(provider="aws", profile="default", report_dir="/tmp/scout-suite", services=None, exceptions=None, additional_args=None)` registered as `"scout_suite_scan"` at `/api/tools/scout-suite`.

**Note:** `--profile` is only emitted when `profile and provider == "aws"` — a compound condition. For any non-`"aws"` provider, `--profile` is never emitted even if `profile` is truthy.

- [ ] **Step 1: Write the failing test**

```python
def test_scout_suite_scan_handler_invocation_aws(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("scout_suite_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/scout-suite"

    report_dir = str(tmp_path / "scout-report")
    res = tool.handler(
        provider="aws", profile="myprofile", report_dir=report_dir,
        services="s3,ec2", exceptions="exc.json", additional_args="--no-browser",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "scout", "aws",
        "--profile", "myprofile",
        "--services", "s3,ec2",
        "--exceptions", "exc.json",
        "--report-dir", report_dir,
        "--no-browser",
    ]
    assert res["report_directory"] == report_dir
    assert Path(report_dir).is_dir()


def test_scout_suite_scan_handler_invocation_non_aws_skips_profile(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("scout_suite_scan")

    report_dir = str(tmp_path / "scout-report-azure")
    res = tool.handler(provider="azure", profile="myprofile", report_dir=report_dir)
    assert res["success"] is True
    assert captured["cmd"] == ["scout", "azure", "--report-dir", report_dir]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -k scout_suite -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="scout_suite_scan",
    category="cloud",
    description="Multi-cloud security assessment using Scout Suite",
    endpoint="/api/tools/scout-suite"
)
def scout_suite_scan(provider: str = "aws", profile: Optional[str] = "default", report_dir: str = "/tmp/scout-suite", services: Optional[str] = None, exceptions: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["scout", provider]
    if profile and provider == "aws":
        cmd.extend(["--profile", profile])
    if services:
        cmd.extend(["--services", services])
    if exceptions:
        cmd.extend(["--exceptions", exceptions])
    cmd.extend(["--report-dir", report_dir])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    result["report_directory"] = report_dir
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port scout_suite_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 4: `cloudmapper_run`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `cloudmapper_run(action="collect", account=None, config="config.json", additional_args=None)` registered as `"cloudmapper_run"` at `/api/tools/cloudmapper`.

**Note:** legacy required `account` OR `action == "webserver"`; per Global Constraints, leave `account` `Optional`/`None` and skip manual validation.

- [ ] **Step 1: Write the failing test**

```python
def test_cloudmapper_run_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("cloudmapper_run")
    assert tool is not None
    assert tool.endpoint == "/api/tools/cloudmapper"

    res = tool.handler(action="collect", account="123456789", config="myconfig.json", additional_args="--verbose")
    assert res["success"] is True
    assert captured["cmd"] == ["cloudmapper", "collect", "--account", "123456789", "--config", "myconfig.json", "--verbose"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_cloudmapper_run_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="cloudmapper_run",
    category="cloud",
    description="AWS network visualization and security analysis using CloudMapper",
    endpoint="/api/tools/cloudmapper"
)
def cloudmapper_run(action: str = "collect", account: Optional[str] = None, config: Optional[str] = "config.json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["cloudmapper", action]
    if account:
        cmd.extend(["--account", account])
    if config:
        cmd.extend(["--config", config])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port cloudmapper_run to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 5: `kube_hunter_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `kube_hunter_scan(target=None, remote=None, cidr=None, interface=None, active=False, report="json", additional_args=None)` registered as `"kube_hunter_scan"` at `/api/tools/kube-hunter`.

**Note:** the `target`/`remote`/`cidr`/`interface`/default-to-`--pod` chain is an `if/elif/elif/elif/else` — strict priority order, not independent ifs. Only one of `--remote`/`--cidr`/`--interface`/`--pod` is ever emitted.

- [ ] **Step 1: Write the failing test**

```python
def test_kube_hunter_scan_handler_invocation_target(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/kube-hunter"

    res = tool.handler(target="10.0.0.1", active=True, report="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--remote", "10.0.0.1", "--active", "--report", "json", "-v"]


def test_kube_hunter_scan_handler_invocation_default_pod(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")

    res = tool.handler(report="json")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--pod", "--report", "json"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -k kube_hunter -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="kube_hunter_scan",
    category="cloud",
    description="Kubernetes penetration testing using kube-hunter",
    endpoint="/api/tools/kube-hunter"
)
def kube_hunter_scan(target: Optional[str] = None, remote: Optional[str] = None, cidr: Optional[str] = None, interface: Optional[str] = None, active: bool = False, report: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["kube-hunter"]
    if target:
        cmd.extend(["--remote", target])
    elif remote:
        cmd.extend(["--remote", remote])
    elif cidr:
        cmd.extend(["--cidr", cidr])
    elif interface:
        cmd.extend(["--interface", interface])
    else:
        cmd.append("--pod")
    if active:
        cmd.append("--active")
    if report:
        cmd.extend(["--report", report])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port kube_hunter_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 6: `kube_bench_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `kube_bench_scan(targets=None, version=None, config_dir=None, output_format="json", additional_args=None)` registered as `"kube_bench_scan"` at `/api/tools/kube-bench`.

**Note:** when `output_format` is truthy, THREE tokens are emitted together: `--outputfile`, `/tmp/kube-bench-results.{output_format}`, `--json` — the literal `--json` flag is always appended alongside, regardless of what `output_format`'s actual value is (even if it isn't literally `"json"`). Preserve this exactly.

- [ ] **Step 1: Write the failing test**

```python
def test_kube_bench_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_bench_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/kube-bench"

    res = tool.handler(targets="master,node", version="1.23", config_dir="/etc/kube-bench", output_format="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == [
        "kube-bench", "--targets", "master,node", "--version", "1.23", "--config-dir", "/etc/kube-bench",
        "--outputfile", "/tmp/kube-bench-results.json", "--json", "-v",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_kube_bench_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="kube_bench_scan",
    category="cloud",
    description="CIS Kubernetes benchmark checks using kube-bench",
    endpoint="/api/tools/kube-bench"
)
def kube_bench_scan(targets: Optional[str] = None, version: Optional[str] = None, config_dir: Optional[str] = None, output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["kube-bench"]
    if targets:
        cmd.extend(["--targets", targets])
    if version:
        cmd.extend(["--version", version])
    if config_dir:
        cmd.extend(["--config-dir", config_dir])
    if output_format:
        cmd.extend(["--outputfile", f"/tmp/kube-bench-results.{output_format}", "--json"])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port kube_bench_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 7: `docker_bench_security_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `docker_bench_security_scan(checks=None, exclude=None, output_file="/tmp/docker-bench-results.json", additional_args=None)` registered as `"docker_bench_security_scan"` at `/api/tools/docker-bench-security`.

**Note:** `result["output_file"] = output_file` is set **unconditionally** after `run_tool_command` — the legacy code has no `if output_file:` guard around this assignment (unlike Task 2's `trivy_scan`), because `output_file` always has a non-empty default. Do not add a guard that wasn't there.

- [ ] **Step 1: Write the failing test**

```python
def test_docker_bench_security_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("docker_bench_security_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/docker-bench-security"

    res = tool.handler(checks="check1", exclude="check2", output_file="/tmp/custom.json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["docker-bench-security", "-c", "check1", "-e", "check2", "-l", "/tmp/custom.json", "-v"]
    assert res["output_file"] == "/tmp/custom.json"

    res2 = tool.handler()
    assert res2["output_file"] == "/tmp/docker-bench-results.json"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_docker_bench_security_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="docker_bench_security_scan",
    category="cloud",
    description="Docker security assessment using Docker Bench for Security",
    endpoint="/api/tools/docker-bench-security"
)
def docker_bench_security_scan(checks: Optional[str] = None, exclude: Optional[str] = None, output_file: str = "/tmp/docker-bench-results.json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["docker-bench-security"]
    if checks:
        cmd.extend(["-c", checks])
    if exclude:
        cmd.extend(["-e", exclude])
    if output_file:
        cmd.extend(["-l", output_file])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    result["output_file"] = output_file
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port docker_bench_security_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 8: `falco_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `falco_scan(config_file="/etc/falco/falco.yaml", rules_file=None, output_format="json", duration=60, additional_args=None)` registered as `"falco_scan"` at `/api/tools/falco`.

- [ ] **Step 1: Write the failing test**

```python
def test_falco_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("falco_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/falco"

    res = tool.handler(config_file="/tmp/falco.yaml", rules_file="/tmp/rules.yaml", output_format="json", duration=30, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["timeout", "30", "falco", "--config", "/tmp/falco.yaml", "--rules", "/tmp/rules.yaml", "--json", "-v"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_falco_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="falco_scan",
    category="cloud",
    description="Runtime security monitoring using Falco",
    endpoint="/api/tools/falco"
)
def falco_scan(config_file: str = "/etc/falco/falco.yaml", rules_file: Optional[str] = None, output_format: str = "json", duration: int = 60, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["timeout", str(duration), "falco"]
    if config_file:
        cmd.extend(["--config", config_file])
    if rules_file:
        cmd.extend(["--rules", rules_file])
    if output_format == "json":
        cmd.append("--json")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port falco_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 9: `clair_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `clair_scan(image, config="/etc/clair/config.yaml", output_format="json", additional_args=None)` registered as `"clair_scan"` at `/api/tools/clair`.

**Note:** legacy uses the `clairctl` binary (not `clair` directly), invoked as `clairctl analyze {image}` — a two-word subcommand.

- [ ] **Step 1: Write the failing test**

```python
def test_clair_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("clair_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/clair"

    res = tool.handler(image="myimage:latest", config="/tmp/clair.yaml", output_format="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["clairctl", "analyze", "myimage:latest", "--config", "/tmp/clair.yaml", "--format", "json", "-v"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_clair_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="clair_scan",
    category="cloud",
    description="Container vulnerability analysis using Clair",
    endpoint="/api/tools/clair"
)
def clair_scan(image: str, config: str = "/etc/clair/config.yaml", output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["clairctl", "analyze", image]
    if config:
        cmd.extend(["--config", config])
    if output_format:
        cmd.extend(["--format", output_format])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port clair_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 10: `checkov_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `checkov_scan(directory=".", framework=None, check=None, skip_check=None, output_format="json", additional_args=None)` registered as `"checkov_scan"` at `/api/tools/checkov`.

- [ ] **Step 1: Write the failing test**

```python
def test_checkov_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("checkov_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/checkov"

    res = tool.handler(
        directory="/tmp/iac", framework="terraform", check="CKV_AWS_1",
        skip_check="CKV_AWS_2", output_format="json", additional_args="--compact",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "checkov", "-d", "/tmp/iac",
        "--framework", "terraform", "--check", "CKV_AWS_1", "--skip-check", "CKV_AWS_2",
        "--output", "json", "--compact",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_checkov_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="checkov_scan",
    category="cloud",
    description="Infrastructure as code security scanning using Checkov",
    endpoint="/api/tools/checkov"
)
def checkov_scan(directory: str = ".", framework: Optional[str] = None, check: Optional[str] = None, skip_check: Optional[str] = None, output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["checkov", "-d", directory]
    if framework:
        cmd.extend(["--framework", framework])
    if check:
        cmd.extend(["--check", check])
    if skip_check:
        cmd.extend(["--skip-check", skip_check])
    if output_format:
        cmd.extend(["--output", output_format])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port checkov_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 11: `terrascan_scan`

**Files:**
- Modify: `hexstrike/tools/cloud.py`
- Test: `tests/test_cloud_tools.py`

**Interfaces:**
- Produces: `terrascan_scan(scan_type="all", iac_dir=".", policy_type=None, output_format="json", severity=None, additional_args=None)` registered as `"terrascan_scan"` at `/api/tools/terrascan`.

- [ ] **Step 1: Write the failing test**

```python
def test_terrascan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("terrascan_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/terrascan"

    res = tool.handler(
        scan_type="terraform", iac_dir="/tmp/iac", policy_type="aws",
        output_format="json", severity="HIGH", additional_args="--non-recursive",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "terrascan", "scan", "-t", "terraform", "-d", "/tmp/iac",
        "-p", "aws", "-o", "json", "--severity", "HIGH", "--non-recursive",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py::test_terrascan_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="terrascan_scan",
    category="cloud",
    description="Infrastructure as code security scanning using Terrascan",
    endpoint="/api/tools/terrascan"
)
def terrascan_scan(scan_type: str = "all", iac_dir: str = ".", policy_type: Optional[str] = None, output_format: str = "json", severity: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["terrascan", "scan", "-t", scan_type, "-d", iac_dir]
    if policy_type:
        cmd.extend(["-p", policy_type])
    if output_format:
        cmd.extend(["-o", output_format])
    if severity:
        cmd.extend(["--severity", severity])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_cloud_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/cloud.py tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port terrascan_scan to cloud tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 12: Full verification

**Files:** none created/modified beyond one test addition.

**Interfaces:**
- Consumes: `ToolRegistry.get_by_category("cloud")` from `hexstrike/core/registry.py`.

- [ ] **Step 1: Assert cloud category has exactly 11 tools**

Add to `tests/test_cloud_tools.py`:

```python
def test_cloud_category_has_11_tools():
    from hexstrike.core.registry import ToolRegistry
    import hexstrike.tools
    cloud_tools = ToolRegistry.get_by_category("cloud")
    assert len(cloud_tools) == 11
    names = {t.name for t in cloud_tools}
    assert names == {
        "prowler_scan", "trivy_scan", "scout_suite_scan", "cloudmapper_run",
        "kube_hunter_scan", "kube_bench_scan", "docker_bench_security_scan",
        "falco_scan", "clair_scan", "checkov_scan", "terrascan_scan",
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
    assert 'prowler_scan' in names
    assert 'terrascan_scan' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```
Expected: no assertion error, prints a tool count of at least 53 (42 pre-existing + 11 new).

- [ ] **Step 4: Commit**

```bash
git add tests/test_cloud_tools.py
git commit -m "$(cat <<'EOF'
test(tools): verify cloud category reaches 11-tool parity for the mechanical subset

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```
