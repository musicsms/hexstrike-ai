# Web Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port 20 mechanical CLI-wrapper web-category tools from the legacy monolith (`hexstrike_server.py` at commit `d689933`) into the modular `hexstrike/tools/web.py` registry, extending the category from 3 tools (`ffuf_fuzz`, `gobuster_dir`, `sqlmap_scan`) to 23.

**Architecture:** Each tool is a single Python function decorated with `@ToolRegistry.register(...)`, appended to `hexstrike/tools/web.py`. Each function builds a `List[str]` command (never a shell string) and returns `run_tool_command(cmd)` from `hexstrike/tools/base.py`. This is the exact pattern already established and verified across 22 tools in the `network` category (see `docs/superpowers/plans/2026-09-09-network-tools-migration.md`).

**Tech Stack:** Python 3.13, pytest, Flask (via `hexstrike.api.app.create_app`), FastMCP (via `hexstrike.mcp.server.setup_mcp_server`) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md` (approved architecture this plan extends). Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

**Explicit scope boundary:** the `web` category in the legacy monolith has 29 remaining tools total, not 20. This plan covers only the 20 that are simple CLI wrappers matching the established mechanical pattern. The other 9 are explicitly OUT of scope for this plan and must NOT be added to `hexstrike/tools/web.py` here — they need separate design work first:
- `anew`, `qsreplace`, `uro`, `hakrawler` — legacy piped input via a shell `echo url | tool` construct. The new architecture's `ProcessManager.execute_command` (in `hexstrike/core/process.py`) has no stdin-input parameter today; these need that capability added first, as its own plan.
- `jwt_analyzer`, `api_fuzzer`, `api_schema_analyzer`, `graphql_scanner` — legacy either does pure-Python logic with no subprocess (`jwt_analyzer`) or shells out to `curl` via a hand-built shell string (the other three). These need a design decision (e.g. use the `requests` library instead of shelling out) before porting, as their own plan.
- `http-framework`, `burpsuite-alternative` — stateful, multi-action endpoints backed by the legacy `HTTPTestingFramework` and `BrowserAgent` (Selenium) classes, not simple one-shot CLI wrappers. Porting these means porting those classes first — a much larger, separate effort.

## Global Constraints

- **Verbatim behavior**: command construction, flag names, and default values must match the legacy monolith exactly, with exactly ONE documented exception in this plan (Task 12, `nuclei_scan` — see its task for details).
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True` (see `hexstrike/core/process.py:37-43`). A legacy single-quoted shell argument (e.g. `--custom-payload '{x}'`) becomes one list element holding the raw value — no manual quoting needed, since there is no shell to escape for.
- **`additional_args` handling**: always optional (`Optional[str] = None`), appended via simple `additional_args.split()` (whitespace split, matching the network-category convention — not `shlex.split`).
- **Legacy manual validation is not reproduced**: the old Flask routes did `if not url: return jsonify({"error": ...}), 400`. The new pattern instead makes the field a required parameter with no default; a missing value raises `TypeError`, which `hexstrike/api/app.py:15-20` already converts to a 400 response. Do not re-add manual `if not X` checks. Two tools (`dalfox_scan`, `zap_scan`) have a legacy either-or requirement (`url` OR `pipe_mode`; `target` OR `daemon`) — per the network-category precedent (`arp_scan`), leave both as `Optional` and do not hand-roll the either-or validation.
- **Parameter names are part of the public API/MCP schema** — do not rename a parameter from what the legacy route used as its JSON key, even if it shadows a Python builtin. This plan has two such cases: `format` in `zap_scan` (Task 20) and `params` in `xsser_scan` (Task 19).
- Every task must leave `./.venv/bin/python3 -m pytest tests/ -v` (or the equivalent venv in whatever workspace this plan executes in) fully green before commit.
- **Commit attribution**: every commit trailer must read exactly:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
  ```
  Use this literal text verbatim — do not substitute an implementer's own model identity (this happened once during the network-tools migration and had to be fixed).

---

### Task 1: `arjun_scan`

**Files:**
- Modify: `hexstrike/tools/web.py` (append function)
- Test: `tests/test_web_tools.py` (create file)

**Interfaces:**
- Consumes: `run_tool_command(cmd: List[str], timeout: int = 300, use_cache: bool = True) -> Dict[str, Any]` from `hexstrike/tools/base.py`; `ToolRegistry.register(...)` decorator and `ToolRegistry.get(name) -> ToolSpec` from `hexstrike/core/registry.py`.
- Produces: `arjun_scan(url, method="GET", wordlist=None, delay=0, threads=25, stable=False, additional_args=None)` registered as tool name `"arjun_scan"` at endpoint `/api/tools/arjun`, category `"web"`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_web_tools.py`:

```python
import pytest
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


def test_arjun_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("arjun_scan")
    assert tool is not None
    assert tool.category == "web"
    assert tool.endpoint == "/api/tools/arjun"

    res = tool.handler(
        url="http://x.com", method="POST", wordlist="/tmp/wl.txt",
        delay=2, threads=10, stable=True, additional_args="--include X",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "arjun", "-u", "http://x.com", "-m", "POST", "-t", "10",
        "-w", "/tmp/wl.txt", "-d", "2", "--stable", "--include", "X",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: FAIL — `ToolRegistry.get("arjun_scan")` returns `None`.

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/tools/web.py`:

```python
@ToolRegistry.register(
    name="arjun_scan",
    category="web",
    description="HTTP parameter discovery using Arjun",
    endpoint="/api/tools/arjun"
)
def arjun_scan(url: str, method: str = "GET", wordlist: Optional[str] = None, delay: int = 0, threads: int = 25, stable: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["arjun", "-u", url, "-m", method, "-t", str(threads)]
    if wordlist:
        cmd.extend(["-w", wordlist])
    if delay > 0:
        cmd.extend(["-d", str(delay)])
    if stable:
        cmd.append("--stable")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

(Check the top of `hexstrike/tools/web.py` already imports `Dict`, `Any`, `Optional` from `typing`, `ToolRegistry`, and `run_tool_command` — it should, matching `network.py`'s header. If any import is missing, add it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port arjun_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 2: `dalfox_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `dalfox_scan(url=None, pipe_mode=False, blind=False, mining_dom=True, mining_dict=True, custom_payload=None, additional_args=None)` registered as `"dalfox_scan"` at `/api/tools/dalfox`.

**Note:** legacy required `url` OR `pipe_mode`. Per Global Constraints, leave both `Optional`/default — do not add manual validation.

- [ ] **Step 1: Write the failing test**

```python
def test_dalfox_scan_handler_invocation_url_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dalfox_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dalfox"

    res = tool.handler(
        url="http://x.com", blind=True, mining_dom=True, mining_dict=True,
        custom_payload="<script>", additional_args="--silence",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "dalfox", "url", "http://x.com", "--blind", "--mining-dom", "--mining-dict",
        "--custom-payload", "<script>", "--silence",
    ]


def test_dalfox_scan_handler_invocation_pipe_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dalfox_scan")

    res = tool.handler(pipe_mode=True, mining_dom=False, mining_dict=False)
    assert res["success"] is True
    assert captured["cmd"] == ["dalfox", "pipe"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -k dalfox -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="dalfox_scan",
    category="web",
    description="Advanced XSS vulnerability scanning using Dalfox",
    endpoint="/api/tools/dalfox"
)
def dalfox_scan(url: Optional[str] = None, pipe_mode: bool = False, blind: bool = False, mining_dom: bool = True, mining_dict: bool = True, custom_payload: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    if pipe_mode:
        cmd = ["dalfox", "pipe"]
    else:
        cmd = ["dalfox", "url", url]
    if blind:
        cmd.append("--blind")
    if mining_dom:
        cmd.append("--mining-dom")
    if mining_dict:
        cmd.append("--mining-dict")
    if custom_payload:
        cmd.extend(["--custom-payload", custom_payload])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port dalfox_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 3: `dirb_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `dirb_scan(url, wordlist="/usr/share/wordlists/dirb/common.txt", additional_args=None)` registered as `"dirb_scan"` at `/api/tools/dirb`.

- [ ] **Step 1: Write the failing test**

```python
def test_dirb_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dirb_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dirb"

    res = tool.handler(url="http://x.com", additional_args="-S")
    assert res["success"] is True
    assert captured["cmd"] == ["dirb", "http://x.com", "/usr/share/wordlists/dirb/common.txt", "-S"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_dirb_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="dirb_scan",
    category="web",
    description="Directory and file brute-forcing using dirb",
    endpoint="/api/tools/dirb"
)
def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dirb", url, wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port dirb_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 4: `dirsearch_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `dirsearch_scan(url, extensions="php,html,js,txt,xml,json", wordlist="/usr/share/wordlists/dirsearch/common.txt", threads=30, recursive=False, additional_args=None)` registered as `"dirsearch_scan"` at `/api/tools/dirsearch`.

- [ ] **Step 1: Write the failing test**

```python
def test_dirsearch_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dirsearch_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dirsearch"

    res = tool.handler(url="http://x.com", extensions="php", wordlist="/tmp/wl.txt", threads=5, recursive=True, additional_args="-f")
    assert res["success"] is True
    assert captured["cmd"] == ["dirsearch", "-u", "http://x.com", "-e", "php", "-w", "/tmp/wl.txt", "-t", "5", "-r", "-f"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_dirsearch_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="dirsearch_scan",
    category="web",
    description="Advanced directory and file discovery using Dirsearch",
    endpoint="/api/tools/dirsearch"
)
def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json", wordlist: str = "/usr/share/wordlists/dirsearch/common.txt", threads: int = 30, recursive: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dirsearch", "-u", url, "-e", extensions, "-w", wordlist, "-t", str(threads)]
    if recursive:
        cmd.append("-r")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port dirsearch_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 5: `dotdotpwn_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `dotdotpwn_scan(target, module="http", additional_args=None)` registered as `"dotdotpwn_scan"` at `/api/tools/dotdotpwn`.

**Note:** legacy always appends `-b` LAST, after `additional_args` — preserve that exact order.

- [ ] **Step 1: Write the failing test**

```python
def test_dotdotpwn_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dotdotpwn_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dotdotpwn"

    res = tool.handler(target="10.0.0.1", module="ftp", additional_args="-t 300")
    assert res["success"] is True
    assert captured["cmd"] == ["dotdotpwn", "-m", "ftp", "-h", "10.0.0.1", "-t", "300", "-b"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_dotdotpwn_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="dotdotpwn_scan",
    category="web",
    description="Directory traversal fuzzing using DotDotPwn",
    endpoint="/api/tools/dotdotpwn"
)
def dotdotpwn_scan(target: str, module: str = "http", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dotdotpwn", "-m", module, "-h", target]
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append("-b")
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port dotdotpwn_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 6: `feroxbuster_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `feroxbuster_scan(url, wordlist="/usr/share/wordlists/dirb/common.txt", threads=10, additional_args=None)` registered as `"feroxbuster_scan"` at `/api/tools/feroxbuster`.

- [ ] **Step 1: Write the failing test**

```python
def test_feroxbuster_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("feroxbuster_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/feroxbuster"

    res = tool.handler(url="http://x.com", wordlist="/tmp/wl.txt", threads=20, additional_args="-A")
    assert res["success"] is True
    assert captured["cmd"] == ["feroxbuster", "-u", "http://x.com", "-w", "/tmp/wl.txt", "-t", "20", "-A"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_feroxbuster_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="feroxbuster_scan",
    category="web",
    description="Recursive content discovery using Feroxbuster",
    endpoint="/api/tools/feroxbuster"
)
def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "-t", str(threads)]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port feroxbuster_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 7: `gau_discover`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `gau_discover(domain, providers="wayback,commoncrawl,otx,urlscan", include_subs=True, blacklist="png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", additional_args=None)` registered as `"gau_discover"` at `/api/tools/gau`.

**Note:** `--providers` is only emitted when `providers` differs from its own default string — this is a legitimate default-suppression check (unlike the `autorecon_scan` quirk from the network plan), since the comparison value equals the actual default. Preserve the literal string comparison.

- [ ] **Step 1: Write the failing test**

```python
def test_gau_discover_handler_invocation_default_providers(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gau_discover")
    assert tool is not None
    assert tool.endpoint == "/api/tools/gau"

    res = tool.handler(domain="example.com", additional_args="--threads 5")
    assert res["success"] is True
    assert captured["cmd"] == [
        "gau", "example.com", "--subs",
        "--blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
        "--threads", "5",
    ]


def test_gau_discover_handler_invocation_custom_providers(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gau_discover")

    res = tool.handler(domain="example.com", providers="wayback", include_subs=False, blacklist="")
    assert res["success"] is True
    assert captured["cmd"] == ["gau", "example.com", "--providers", "wayback"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -k gau_discover -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="gau_discover",
    category="web",
    description="URL discovery from multiple archive sources using Gau",
    endpoint="/api/tools/gau"
)
def gau_discover(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan", include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gau", domain]
    if providers != "wayback,commoncrawl,otx,urlscan":
        cmd.extend(["--providers", providers])
    if include_subs:
        cmd.append("--subs")
    if blacklist:
        cmd.extend(["--blacklist", blacklist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port gau_discover to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 8: `httpx_probe`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `httpx_probe(target, probe=True, tech_detect=False, status_code=False, content_length=False, title=False, web_server=False, threads=50, additional_args=None)` registered as `"httpx_probe"` at `/api/tools/httpx`.

- [ ] **Step 1: Write the failing test**

```python
def test_httpx_probe_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("httpx_probe")
    assert tool is not None
    assert tool.endpoint == "/api/tools/httpx"

    res = tool.handler(
        target="http://x.com", probe=True, tech_detect=True, status_code=True,
        content_length=True, title=True, web_server=True, threads=25, additional_args="-json",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "httpx", "-l", "http://x.com", "-t", "25",
        "-probe", "-tech-detect", "-sc", "-cl", "-title", "-server", "-json",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_httpx_probe_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="httpx_probe",
    category="web",
    description="Fast HTTP probing and technology detection using httpx",
    endpoint="/api/tools/httpx"
)
def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False, status_code: bool = False, content_length: bool = False, title: bool = False, web_server: bool = False, threads: int = 50, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["httpx", "-l", target, "-t", str(threads)]
    if probe:
        cmd.append("-probe")
    if tech_detect:
        cmd.append("-tech-detect")
    if status_code:
        cmd.append("-sc")
    if content_length:
        cmd.append("-cl")
    if title:
        cmd.append("-title")
    if web_server:
        cmd.append("-server")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port httpx_probe to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 9: `jaeles_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `jaeles_scan(url, signatures=None, config=None, threads=20, timeout=20, additional_args=None)` registered as `"jaeles_scan"` at `/api/tools/jaeles`.

- [ ] **Step 1: Write the failing test**

```python
def test_jaeles_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("jaeles_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/jaeles"

    res = tool.handler(url="http://x.com", signatures="/tmp/sigs", config="/tmp/cfg", threads=5, timeout=10, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == [
        "jaeles", "scan", "-u", "http://x.com", "-c", "5", "--timeout", "10",
        "-s", "/tmp/sigs", "--config", "/tmp/cfg", "-v",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_jaeles_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="jaeles_scan",
    category="web",
    description="Advanced vulnerability scanning with custom signatures using Jaeles",
    endpoint="/api/tools/jaeles"
)
def jaeles_scan(url: str, signatures: Optional[str] = None, config: Optional[str] = None, threads: int = 20, timeout: int = 20, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["jaeles", "scan", "-u", url, "-c", str(threads), "--timeout", str(timeout)]
    if signatures:
        cmd.extend(["-s", signatures])
    if config:
        cmd.extend(["--config", config])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port jaeles_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 10: `katana_crawl`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `katana_crawl(url, depth=3, js_crawl=True, form_extraction=True, output_format="json", additional_args=None)` registered as `"katana_crawl"` at `/api/tools/katana`.

**Note:** `-jsonl` is emitted only when `output_format == "json"` literally — any other value (including e.g. `"jsonl"` itself) emits nothing. Preserve this exact comparison, don't "fix" it to be more permissive.

- [ ] **Step 1: Write the failing test**

```python
def test_katana_crawl_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("katana_crawl")
    assert tool is not None
    assert tool.endpoint == "/api/tools/katana"

    res = tool.handler(url="http://x.com", depth=5, js_crawl=True, form_extraction=True, output_format="json", additional_args="-silent")
    assert res["success"] is True
    assert captured["cmd"] == ["katana", "-u", "http://x.com", "-d", "5", "-jc", "-fx", "-jsonl", "-silent"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_katana_crawl_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="katana_crawl",
    category="web",
    description="Next-generation web crawling and spidering using Katana",
    endpoint="/api/tools/katana"
)
def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True, form_extraction: bool = True, output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["katana", "-u", url, "-d", str(depth)]
    if js_crawl:
        cmd.append("-jc")
    if form_extraction:
        cmd.append("-fx")
    if output_format == "json":
        cmd.append("-jsonl")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port katana_crawl to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 11: `nikto_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `nikto_scan(target, additional_args=None)` registered as `"nikto_scan"` at `/api/tools/nikto`.

- [ ] **Step 1: Write the failing test**

```python
def test_nikto_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nikto_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/nikto"

    res = tool.handler(target="http://x.com", additional_args="-Tuning 1")
    assert res["success"] is True
    assert captured["cmd"] == ["nikto", "-h", "http://x.com", "-Tuning", "1"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_nikto_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="nikto_scan",
    category="web",
    description="Web server vulnerability scanning using Nikto",
    endpoint="/api/tools/nikto"
)
def nikto_scan(target: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nikto", "-h", target]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port nikto_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 12: `nuclei_scan` (intentional simplification — no error-recovery wrapper)

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `nuclei_scan(target, severity=None, tags=None, template=None, additional_args=None)` registered as `"nuclei_scan"` at `/api/tools/nuclei`.

**Intentional deviation (must be called out, not silent):** legacy had a `use_recovery` flag that, when true (its default), routed execution through `execute_command_with_recovery(...)` — part of the legacy monolith's `IntelligentErrorHandler`/retry framework. That framework has not been ported into `hexstrike/core` yet (it's a separate, much larger sub-project — see the "Explicit scope boundary" note at the top of this plan for the pattern of what's out of scope). This task drops the `use_recovery` parameter entirely and always uses the plain execution path (`run_tool_command`, same as every other tool in this plan). The resulting `nuclei` command line itself (flags, ordering) is unaffected — only the retry/recovery wrapper around execution is omitted, pending that framework's own future migration.

- [ ] **Step 1: Write the failing test**

```python
def test_nuclei_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nuclei_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/nuclei"

    res = tool.handler(target="http://x.com", severity="high", tags="cve", template="/tmp/t.yaml", additional_args="-rl 10")
    assert res["success"] is True
    assert captured["cmd"] == ["nuclei", "-u", "http://x.com", "-severity", "high", "-tags", "cve", "-t", "/tmp/t.yaml", "-rl", "10"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_nuclei_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="nuclei_scan",
    category="web",
    description="Vulnerability scanning using Nuclei templates",
    endpoint="/api/tools/nuclei"
)
def nuclei_scan(target: str, severity: Optional[str] = None, tags: Optional[str] = None, template: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nuclei", "-u", target]
    if severity:
        cmd.extend(["-severity", severity])
    if tags:
        cmd.extend(["-tags", tags])
    if template:
        cmd.extend(["-t", template])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port nuclei_scan to web tool registry

Drops the legacy use_recovery/execute_command_with_recovery wrapper,
since the IntelligentErrorHandler framework it depends on has not
been ported into hexstrike/core yet. The nuclei command itself
(flags, ordering) is unaffected; only the retry wrapper is omitted
pending that framework's own future migration.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 13: `paramspider_mine`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `paramspider_mine(domain, level=2, exclude="png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", output=None, additional_args=None)` registered as `"paramspider_mine"` at `/api/tools/paramspider`.

- [ ] **Step 1: Write the failing test**

```python
def test_paramspider_mine_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("paramspider_mine")
    assert tool is not None
    assert tool.endpoint == "/api/tools/paramspider"

    res = tool.handler(domain="example.com", level=3, exclude="png,jpg", output="/tmp/out.txt", additional_args="-q")
    assert res["success"] is True
    assert captured["cmd"] == ["paramspider", "-d", "example.com", "-l", "3", "--exclude", "png,jpg", "-o", "/tmp/out.txt", "-q"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_paramspider_mine_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="paramspider_mine",
    category="web",
    description="Parameter mining from web archives using ParamSpider",
    endpoint="/api/tools/paramspider"
)
def paramspider_mine(domain: str, level: int = 2, exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", output: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["paramspider", "-d", domain, "-l", str(level)]
    if exclude:
        cmd.extend(["--exclude", exclude])
    if output:
        cmd.extend(["-o", output])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port paramspider_mine to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 14: `wafw00f_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `wafw00f_scan(target, additional_args=None)` registered as `"wafw00f_scan"` at `/api/tools/wafw00f`.

- [ ] **Step 1: Write the failing test**

```python
def test_wafw00f_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("wafw00f_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/wafw00f"

    res = tool.handler(target="http://x.com", additional_args="-a")
    assert res["success"] is True
    assert captured["cmd"] == ["wafw00f", "http://x.com", "-a"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_wafw00f_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="wafw00f_scan",
    category="web",
    description="WAF fingerprinting using wafw00f",
    endpoint="/api/tools/wafw00f"
)
def wafw00f_scan(target: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wafw00f", target]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port wafw00f_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 15: `waybackurls_discover`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `waybackurls_discover(domain, get_versions=False, no_subs=False, additional_args=None)` registered as `"waybackurls_discover"` at `/api/tools/waybackurls`.

- [ ] **Step 1: Write the failing test**

```python
def test_waybackurls_discover_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("waybackurls_discover")
    assert tool is not None
    assert tool.endpoint == "/api/tools/waybackurls"

    res = tool.handler(domain="example.com", get_versions=True, no_subs=True, additional_args="-d")
    assert res["success"] is True
    assert captured["cmd"] == ["waybackurls", "example.com", "--get-versions", "--no-subs", "-d"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_waybackurls_discover_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="waybackurls_discover",
    category="web",
    description="Historical URL discovery using Waybackurls",
    endpoint="/api/tools/waybackurls"
)
def waybackurls_discover(domain: str, get_versions: bool = False, no_subs: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["waybackurls", domain]
    if get_versions:
        cmd.append("--get-versions")
    if no_subs:
        cmd.append("--no-subs")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port waybackurls_discover to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 16: `wfuzz_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `wfuzz_scan(url, wordlist="/usr/share/wordlists/dirb/common.txt", additional_args=None)` registered as `"wfuzz_scan"` at `/api/tools/wfuzz`.

**Note:** legacy single-quoted the URL (`'{url}'`) purely for shell-safety (URLs often contain `?`, `&`, etc. that a shell would otherwise interpret) — with `List[str]` there is no shell, so `url` is simply passed as one element, with identical effective behavior.

- [ ] **Step 1: Write the failing test**

```python
def test_wfuzz_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("wfuzz_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/wfuzz"

    res = tool.handler(url="http://x.com/FUZZ", wordlist="/tmp/wl.txt", additional_args="-c")
    assert res["success"] is True
    assert captured["cmd"] == ["wfuzz", "-w", "/tmp/wl.txt", "http://x.com/FUZZ", "-c"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_wfuzz_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="wfuzz_scan",
    category="web",
    description="Web application fuzzing using Wfuzz",
    endpoint="/api/tools/wfuzz"
)
def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wfuzz", "-w", wordlist, url]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port wfuzz_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 17: `wpscan_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `wpscan_scan(url, additional_args=None)` registered as `"wpscan_scan"` at `/api/tools/wpscan`.

- [ ] **Step 1: Write the failing test**

```python
def test_wpscan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("wpscan_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/wpscan"

    res = tool.handler(url="http://x.com", additional_args="--enumerate p")
    assert res["success"] is True
    assert captured["cmd"] == ["wpscan", "--url", "http://x.com", "--enumerate", "p"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_wpscan_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="wpscan_scan",
    category="web",
    description="WordPress vulnerability scanning using WPScan",
    endpoint="/api/tools/wpscan"
)
def wpscan_scan(url: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wpscan", "--url", url]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port wpscan_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 18: `x8_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `x8_scan(url, wordlist="/usr/share/wordlists/x8/params.txt", method="GET", body=None, headers=None, additional_args=None)` registered as `"x8_scan"` at `/api/tools/x8`.

- [ ] **Step 1: Write the failing test**

```python
def test_x8_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("x8_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/x8"

    res = tool.handler(url="http://x.com", wordlist="/tmp/wl.txt", method="POST", body="a=1", headers="X-Test: 1", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["x8", "-u", "http://x.com", "-w", "/tmp/wl.txt", "-X", "POST", "-b", "a=1", "-H", "X-Test: 1", "-v"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_x8_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="x8_scan",
    category="web",
    description="Hidden parameter discovery using x8",
    endpoint="/api/tools/x8"
)
def x8_scan(url: str, wordlist: str = "/usr/share/wordlists/x8/params.txt", method: str = "GET", body: Optional[str] = None, headers: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["x8", "-u", url, "-w", wordlist, "-X", method]
    if body:
        cmd.extend(["-b", body])
    if headers:
        cmd.extend(["-H", headers])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port x8_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 19: `xsser_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `xsser_scan(url, params=None, additional_args=None)` registered as `"xsser_scan"` at `/api/tools/xsser`.

**Note:** legacy JSON key is `"params"` (renamed to a local variable `params_str` in the route only because the route also had an unrelated `params` dict from `request.json` — that collision doesn't exist in this handler, so the parameter is named `params` directly, matching the public API key). Also note the value is joined into a single `--param=value` token (legacy used `--param='{params_str}'`, single-quoted as ONE shell token) — do not split it into two list elements.

- [ ] **Step 1: Write the failing test**

```python
def test_xsser_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("xsser_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/xsser"

    res = tool.handler(url="http://x.com", params="id=1", additional_args="--Fp")
    assert res["success"] is True
    assert captured["cmd"] == ["xsser", "--url", "http://x.com", "--param=id=1", "--Fp"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py::test_xsser_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="xsser_scan",
    category="web",
    description="XSS vulnerability testing using XSSer",
    endpoint="/api/tools/xsser"
)
def xsser_scan(url: str, params: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["xsser", "--url", url]
    if params:
        cmd.append(f"--param={params}")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port xsser_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 20: `zap_scan`

**Files:**
- Modify: `hexstrike/tools/web.py`
- Test: `tests/test_web_tools.py`

**Interfaces:**
- Produces: `zap_scan(target=None, scan_type="baseline", api_key=None, daemon=False, port="8090", host="0.0.0.0", format="xml", output_file=None, additional_args=None)` registered as `"zap_scan"` at `/api/tools/zap`.

**Note:** parameter named `format` intentionally shadows the Python builtin `format()` — matches the legacy JSON key `"format"`, same precedent as `hash` in the network plan's `netexec_scan`. Legacy required `target` OR `scan_type == "daemon"`; per Global Constraints, leave `target` `Optional` and skip manual validation (same precedent as `arp_scan`/`dalfox_scan`). Two mutually exclusive branches: `daemon=True` builds one command shape, otherwise the "quick scan" shape.

- [ ] **Step 1: Write the failing test**

```python
def test_zap_scan_handler_invocation_quickscan(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("zap_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/zap"

    res = tool.handler(target="http://x.com", format="xml", output_file="/tmp/out", api_key="KEY123", additional_args="-cmd")
    assert res["success"] is True
    assert captured["cmd"] == [
        "zaproxy", "-cmd", "-quickurl", "http://x.com",
        "-quickout", "xml", "-quickprogress", "-dir", "/tmp/out",
        "-config", "api.key=KEY123", "-cmd",
    ]


def test_zap_scan_handler_invocation_daemon(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("zap_scan")

    res = tool.handler(daemon=True, host="127.0.0.1", port="9090", api_key="KEY123")
    assert res["success"] is True
    assert captured["cmd"] == ["zaproxy", "-daemon", "-host", "127.0.0.1", "-port", "9090", "-config", "api.key=KEY123"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -k zap_scan -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="zap_scan",
    category="web",
    description="Web application scanning using OWASP ZAP",
    endpoint="/api/tools/zap"
)
def zap_scan(target: Optional[str] = None, scan_type: str = "baseline", api_key: Optional[str] = None, daemon: bool = False, port: str = "8090", host: str = "0.0.0.0", format: str = "xml", output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    if daemon:
        cmd = ["zaproxy", "-daemon", "-host", host, "-port", port]
        if api_key:
            cmd.extend(["-config", f"api.key={api_key}"])
    else:
        cmd = ["zaproxy", "-cmd", "-quickurl", target]
        if format:
            cmd.extend(["-quickout", format])
        if output_file:
            cmd.extend(["-quickprogress", "-dir", output_file])
        if api_key:
            cmd.extend(["-config", f"api.key={api_key}"])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python3 -m pytest tests/test_web_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/web.py tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port zap_scan to web tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 21: Full verification

**Files:** none created/modified beyond one test addition.

**Interfaces:**
- Consumes: `ToolRegistry.get_by_category("web")` from `hexstrike/core/registry.py`.

- [ ] **Step 1: Assert web category has exactly 23 tools**

Add to `tests/test_web_tools.py`:

```python
def test_web_category_has_23_tools():
    from hexstrike.core.registry import ToolRegistry
    import hexstrike.tools
    web_tools = ToolRegistry.get_by_category("web")
    assert len(web_tools) == 23
    names = {t.name for t in web_tools}
    assert names == {
        "ffuf_fuzz", "gobuster_dir", "sqlmap_scan",
        "arjun_scan", "dalfox_scan", "dirb_scan", "dirsearch_scan", "dotdotpwn_scan",
        "feroxbuster_scan", "gau_discover", "httpx_probe", "jaeles_scan", "katana_crawl",
        "nikto_scan", "nuclei_scan", "paramspider_mine", "wafw00f_scan",
        "waybackurls_discover", "wfuzz_scan", "wpscan_scan", "x8_scan", "xsser_scan", "zap_scan",
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
    assert 'arjun_scan' in names
    assert 'zap_scan' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```
Expected: no assertion error, prints a tool count of at least 42 (22 network + 3 pre-existing web + 20 new web — total registered tools across all categories at time of writing was 22; this task's new tools bring it to 42).

- [ ] **Step 4: Commit**

```bash
git add tests/test_web_tools.py
git commit -m "$(cat <<'EOF'
test(tools): verify web category reaches 23-tool parity for the mechanical subset

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```
