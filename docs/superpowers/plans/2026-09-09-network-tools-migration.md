# Network Tools Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the 14 remaining network-category tool endpoints from the legacy monolith (`hexstrike_server.py` at commit `d689933`) into the modular `hexstrike/tools/network.py` registry, reaching full parity for the `network` category (2 tools already ported → 16 total).

**Architecture:** Each tool is a single Python function decorated with `@ToolRegistry.register(...)`, living in `hexstrike/tools/network.py` alongside the existing `nmap_scan`/`rustscan_scan`. Each function builds a `List[str]` command (never a shell string) and returns `run_tool_command(cmd)` from `hexstrike/tools/base.py`. This mirrors the pattern already established and verified working for `nmap_scan`, `rustscan_scan`, `ffuf_fuzz`, `hydra_attack`, and `amass_enum`.

**Tech Stack:** Python 3.13, pytest, Flask (via `hexstrike.api.app.create_app`), FastMCP (via `hexstrike.mcp.server.setup_mcp_server`) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md` (approved architecture this plan extends). Source-of-truth for original tool behavior: `git show d689933:hexstrike_server.py`.

## Global Constraints

- **Verbatim behavior**: command construction, flag names, and default values must match the legacy monolith exactly, unless explicitly called out as an intentional adaptation below (only one such case: `rpcclient`).
- **No shell strings**: commands are built as `List[str]` and executed via `subprocess.run(command, ...)` with no `shell=True` (see `hexstrike/core/process.py:37-43`). Any legacy tool that relied on shell piping must be adapted to an equivalent non-shell invocation — flag this explicitly when it happens.
- **`additional_args` handling**: always optional (`Optional[str] = None`), appended via simple `additional_args.split()` (whitespace split, matching the existing convention in `nmap_scan`/`hydra_attack` — not `shlex.split`).
- **Legacy manual validation is not reproduced**: the old Flask routes did `if not target: return jsonify({"error": ...}), 400`. The new pattern (already used by `nmap_scan`) instead makes the field a required parameter with no default; a missing value raises `TypeError`, which `hexstrike/api/app.py:15-20` already converts to a 400 response. Do not re-add manual `if not X` checks.
- **Parameter names are part of the public API/MCP schema** — do not rename a parameter from what the legacy route used as its JSON key, even if it shadows a Python builtin (e.g. `hash` in `netexec`).
- Every task must leave `./hexstrike-dev/bin/python3 -m pytest tests/ -v` fully green before commit.

---

### Task 1: `masscan_scan`

**Files:**
- Modify: `hexstrike/tools/network.py` (append function)
- Test: `tests/test_network_tools.py` (create file)

**Interfaces:**
- Consumes: `run_tool_command(cmd: List[str], timeout: int = 300, use_cache: bool = True) -> Dict[str, Any]` from `hexstrike/tools/base.py`; `ToolRegistry.register(...)` decorator and `ToolRegistry.get(name) -> ToolSpec` from `hexstrike/core/registry.py`.
- Produces: `masscan_scan(target, ports="1-65535", rate=1000, interface=None, router_mac=None, source_ip=None, banners=False, additional_args=None)` registered as tool name `"masscan_scan"` at endpoint `/api/tools/masscan`, category `"network"`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_network_tools.py`:

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


def test_masscan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("masscan_scan")
    assert tool is not None
    assert tool.category == "network"
    assert tool.endpoint == "/api/tools/masscan"

    res = tool.handler(
        target="192.168.1.0/24",
        ports="80,443",
        rate=500,
        interface="eth0",
        router_mac="00:11:22:33:44:55",
        source_ip="10.0.0.5",
        banners=True,
        additional_args="--wait 5",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "masscan", "192.168.1.0/24", "-p80,443", "--rate=500",
        "-e", "eth0",
        "--router-mac", "00:11:22:33:44:55",
        "--source-ip", "10.0.0.5",
        "--banners",
        "--wait", "5",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: FAIL — `ToolRegistry.get("masscan_scan")` returns `None` (`AttributeError`/`AssertionError`).

- [ ] **Step 3: Write minimal implementation**

Append to `hexstrike/tools/network.py`:

```python
@ToolRegistry.register(
    name="masscan_scan",
    category="network",
    description="High-speed Internet-scale port scanner using Masscan",
    endpoint="/api/tools/masscan"
)
def masscan_scan(target: str, ports: str = "1-65535", rate: int = 1000, interface: Optional[str] = None, router_mac: Optional[str] = None, source_ip: Optional[str] = None, banners: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}"]
    if interface:
        cmd.extend(["-e", interface])
    if router_mac:
        cmd.extend(["--router-mac", router_mac])
    if source_ip:
        cmd.extend(["--source-ip", source_ip])
    if banners:
        cmd.append("--banners")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port masscan_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 2: `arp_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Consumes: same as Task 1.
- Produces: `arp_scan(target=None, interface=None, local_network=False, timeout=500, retry=3, additional_args=None)` registered as `"arp_scan"` at `/api/tools/arp-scan`.

**Note:** the legacy route required `target` OR `local_network` (manual 400 otherwise). Per Global Constraints, this is not reproduced manually — both stay `Optional`/default `False`; omitting both will raise naturally when `cmd.append(target)` receives `None`, which the API layer's generic exception handler still turns into a 500. This matches the "no manual validation" convention already used elsewhere in this file.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_network_tools.py`:

```python
def test_arp_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("arp_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/arp-scan"

    res = tool.handler(
        interface="eth0",
        local_network=True,
        timeout=200,
        retry=5,
        additional_args="-v",
    )
    assert res["success"] is True
    assert captured["cmd"] == ["arp-scan", "-t", "200", "-r", "5", "-I", "eth0", "-l", "-v"]

    res2 = tool.handler(target="192.168.1.1")
    assert captured["cmd"] == ["arp-scan", "-t", "500", "-r", "3", "192.168.1.1"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_arp_scan_handler_invocation -v`
Expected: FAIL — tool not registered.

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="arp_scan",
    category="network",
    description="Network discovery using arp-scan",
    endpoint="/api/tools/arp-scan"
)
def arp_scan(target: Optional[str] = None, interface: Optional[str] = None, local_network: bool = False, timeout: int = 500, retry: int = 3, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["arp-scan", "-t", str(timeout), "-r", str(retry)]
    if interface:
        cmd.extend(["-I", interface])
    if local_network:
        cmd.append("-l")
    else:
        cmd.append(target)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port arp_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 3: `autorecon_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Consumes: same as Task 1.
- Produces: `autorecon_scan(target, output_dir="/tmp/autorecon", port_scans="top-100-ports", service_scans="default", heartbeat=60, timeout=300, additional_args=None)` registered as `"autorecon_scan"` at `/api/tools/autorecon`.

**Note (preserve exact legacy quirk):** the legacy default for `port_scans` is `"top-100-ports"`, but the flag is only *omitted* when the value equals the literal string `"default"`. Since the default value is not `"default"`, `--port-scans` is emitted **even when the caller passes nothing**. This looks like a mismatched sentinel but is the original, observed behavior — preserve it exactly, don't "fix" it.

- [ ] **Step 1: Write the failing test**

```python
def test_autorecon_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("autorecon_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/autorecon"

    res = tool.handler(target="10.0.0.5")
    assert res["success"] is True
    assert captured["cmd"] == [
        "autorecon", "10.0.0.5", "-o", "/tmp/autorecon",
        "--heartbeat", "60", "--timeout", "300",
        "--port-scans", "top-100-ports",
    ]

    res2 = tool.handler(target="10.0.0.5", port_scans="default", service_scans="all", additional_args="-vv")
    assert captured["cmd"] == [
        "autorecon", "10.0.0.5", "-o", "/tmp/autorecon",
        "--heartbeat", "60", "--timeout", "300",
        "--service-scans", "all", "-vv",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_autorecon_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="autorecon_scan",
    category="network",
    description="Comprehensive automated reconnaissance using AutoRecon",
    endpoint="/api/tools/autorecon"
)
def autorecon_scan(target: str, output_dir: str = "/tmp/autorecon", port_scans: str = "top-100-ports", service_scans: str = "default", heartbeat: int = 60, timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["autorecon", target, "-o", output_dir, "--heartbeat", str(heartbeat), "--timeout", str(timeout)]
    # Preserves original quirk: default ("top-100-ports") differs from the "default" sentinel,
    # so --port-scans is emitted unless the caller explicitly passes "default".
    if port_scans != "default":
        cmd.extend(["--port-scans", port_scans])
    if service_scans != "default":
        cmd.extend(["--service-scans", service_scans])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port autorecon_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 4: `dnsenum_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `dnsenum_scan(domain, dns_server=None, wordlist=None, additional_args=None)` registered as `"dnsenum_scan"` at `/api/tools/dnsenum`.

- [ ] **Step 1: Write the failing test**

```python
def test_dnsenum_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dnsenum_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dnsenum"

    res = tool.handler(domain="example.com", dns_server="8.8.8.8", wordlist="/tmp/wl.txt", additional_args="--threads 5")
    assert res["success"] is True
    assert captured["cmd"] == ["dnsenum", "example.com", "--dnsserver", "8.8.8.8", "--file", "/tmp/wl.txt", "--threads", "5"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_dnsenum_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="dnsenum_scan",
    category="network",
    description="DNS enumeration using dnsenum",
    endpoint="/api/tools/dnsenum"
)
def dnsenum_scan(domain: str, dns_server: Optional[str] = None, wordlist: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dnsenum", domain]
    if dns_server:
        cmd.extend(["--dnsserver", dns_server])
    if wordlist:
        cmd.extend(["--file", wordlist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port dnsenum_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 5: `enum4linux_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `enum4linux_scan(target, additional_args="-a")` registered as `"enum4linux_scan"` at `/api/tools/enum4linux`.

**Note:** legacy places `additional_args` *before* `target` in the command, and defaults it to `"-a"` (not empty) — preserve both.

- [ ] **Step 1: Write the failing test**

```python
def test_enum4linux_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("enum4linux_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/enum4linux"

    res = tool.handler(target="10.0.0.1")
    assert res["success"] is True
    assert captured["cmd"] == ["enum4linux", "-a", "10.0.0.1"]

    res2 = tool.handler(target="10.0.0.1", additional_args="-u guest")
    assert captured["cmd"] == ["enum4linux", "-u", "guest", "10.0.0.1"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_enum4linux_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="enum4linux_scan",
    category="network",
    description="SMB/Windows enumeration using enum4linux",
    endpoint="/api/tools/enum4linux"
)
def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
    cmd = ["enum4linux"] + additional_args.split() + [target]
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port enum4linux_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 6: `enum4linux_ng_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `enum4linux_ng_scan(target, username=None, password=None, domain=None, shares=True, users=True, groups=True, policy=True, additional_args=None)` registered as `"enum4linux_ng_scan"` at `/api/tools/enum4linux-ng`.

- [ ] **Step 1: Write the failing test**

```python
def test_enum4linux_ng_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("enum4linux_ng_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/enum4linux-ng"

    res = tool.handler(
        target="10.0.0.1", username="admin", password="pass123", domain="CORP",
        shares=True, users=True, groups=False, policy=True, additional_args="--verbose",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "enum4linux-ng", "10.0.0.1", "-u", "admin", "-p", "pass123", "-d", "CORP",
        "-A", "S,U,P", "--verbose",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_enum4linux_ng_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="enum4linux_ng_scan",
    category="network",
    description="Advanced SMB enumeration using enum4linux-ng",
    endpoint="/api/tools/enum4linux-ng"
)
def enum4linux_ng_scan(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, shares: bool = True, users: bool = True, groups: bool = True, policy: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["enum4linux-ng", target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-d", domain])
    enum_options = []
    if shares:
        enum_options.append("S")
    if users:
        enum_options.append("U")
    if groups:
        enum_options.append("G")
    if policy:
        enum_options.append("P")
    if enum_options:
        cmd.extend(["-A", ",".join(enum_options)])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port enum4linux_ng_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 7: `fierce_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `fierce_scan(domain, dns_server=None, additional_args=None)` registered as `"fierce_scan"` at `/api/tools/fierce`.

- [ ] **Step 1: Write the failing test**

```python
def test_fierce_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("fierce_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/fierce"

    res = tool.handler(domain="example.com", dns_server="8.8.8.8", additional_args="--wide")
    assert res["success"] is True
    assert captured["cmd"] == ["fierce", "--domain", "example.com", "--dns-servers", "8.8.8.8", "--wide"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_fierce_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="fierce_scan",
    category="network",
    description="DNS reconnaissance using fierce",
    endpoint="/api/tools/fierce"
)
def fierce_scan(domain: str, dns_server: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["fierce", "--domain", domain]
    if dns_server:
        cmd.extend(["--dns-servers", dns_server])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port fierce_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 8: `nbtscan_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `nbtscan_scan(target, verbose=False, timeout=2, additional_args=None)` registered as `"nbtscan_scan"` at `/api/tools/nbtscan`.

- [ ] **Step 1: Write the failing test**

```python
def test_nbtscan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nbtscan_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/nbtscan"

    res = tool.handler(target="192.168.1.0/24", verbose=True, timeout=5, additional_args="-r")
    assert res["success"] is True
    assert captured["cmd"] == ["nbtscan", "-t", "5", "-v", "192.168.1.0/24", "-r"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_nbtscan_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="nbtscan_scan",
    category="network",
    description="NetBIOS name scanning using nbtscan",
    endpoint="/api/tools/nbtscan"
)
def nbtscan_scan(target: str, verbose: bool = False, timeout: int = 2, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nbtscan", "-t", str(timeout)]
    if verbose:
        cmd.append("-v")
    cmd.append(target)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port nbtscan_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 9: `netexec_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `netexec_scan(target, protocol="smb", username=None, password=None, hash=None, module=None, additional_args=None)` registered as `"netexec_scan"` at `/api/tools/netexec`.

**Note:** keep the parameter named `hash` (matches the legacy JSON key `"hash"`, part of the public API/MCP schema) even though it shadows the Python builtin — it's a local parameter, never called as a function within this handler.

- [ ] **Step 1: Write the failing test**

```python
def test_netexec_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("netexec_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/netexec"

    res = tool.handler(
        target="10.0.0.5", protocol="smb", username="admin", password="pass",
        hash="aad3b435b51404eeaad3b435b51404ee", module="mimikatz", additional_args="--local-auth",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "nxc", "smb", "10.0.0.5",
        "-u", "admin", "-p", "pass", "-H", "aad3b435b51404eeaad3b435b51404ee", "-M", "mimikatz",
        "--local-auth",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_netexec_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="netexec_scan",
    category="network",
    description="Network service exploitation using NetExec (formerly CrackMapExec)",
    endpoint="/api/tools/netexec"
)
def netexec_scan(target: str, protocol: str = "smb", username: Optional[str] = None, password: Optional[str] = None, hash: Optional[str] = None, module: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nxc", protocol, target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if hash:
        cmd.extend(["-H", hash])
    if module:
        cmd.extend(["-M", module])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port netexec_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 10: `responder_capture`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `responder_capture(interface="eth0", analyze=False, wpad=True, force_wpad_auth=False, fingerprint=False, duration=300, additional_args=None)` registered as `"responder_capture"` at `/api/tools/responder`.

- [ ] **Step 1: Write the failing test**

```python
def test_responder_capture_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("responder_capture")
    assert tool is not None
    assert tool.endpoint == "/api/tools/responder"

    res = tool.handler(
        interface="eth0", analyze=True, wpad=True, force_wpad_auth=True,
        fingerprint=True, duration=60, additional_args="--verbose",
    )
    assert res["success"] is True
    assert captured["cmd"] == ["timeout", "60", "responder", "-I", "eth0", "-A", "-w", "-F", "-f", "--verbose"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_responder_capture_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="responder_capture",
    category="network",
    description="LLMNR/NBT-NS/mDNS poisoner and credential harvester using Responder",
    endpoint="/api/tools/responder"
)
def responder_capture(interface: str = "eth0", analyze: bool = False, wpad: bool = True, force_wpad_auth: bool = False, fingerprint: bool = False, duration: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["timeout", str(duration), "responder", "-I", interface]
    if analyze:
        cmd.append("-A")
    if wpad:
        cmd.append("-w")
    if force_wpad_auth:
        cmd.append("-F")
    if fingerprint:
        cmd.append("-f")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port responder_capture to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 11: `rpcclient_enum` (intentional adaptation — no shell pipe)

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `rpcclient_enum(target, username=None, password=None, domain=None, commands="enumdomusers;enumdomgroups;querydominfo", additional_args=None)` registered as `"rpcclient_enum"` at `/api/tools/rpcclient`.

**Intentional deviation (must be called out, not silent):** the legacy implementation built a shell pipeline — `echo -e '<commands, ; replaced by newline>' | rpcclient <auth> <target>` — executed via a shell string. The new architecture executes commands as a `List[str]` via `subprocess.run(..., shell=False)` (see Global Constraints), so a literal pipe is not available. `rpcclient` natively supports a `-c "cmd1;cmd2;..."` flag that executes the same semicolon-separated commands directly, with no shell and no `echo`. This plan uses `-c` instead of the echo-pipe. The **set of rpcclient commands executed against the target is identical**; only the transport mechanism changes (native flag vs. shell pipe), and only because a shell pipe isn't a legal `List[str]` command in the first place.

- [ ] **Step 1: Write the failing test**

```python
def test_rpcclient_enum_handler_invocation_authenticated(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("rpcclient_enum")
    assert tool is not None
    assert tool.endpoint == "/api/tools/rpcclient"

    res = tool.handler(
        target="10.0.0.5", username="admin", password="Pass123", domain="CORP",
        commands="enumdomusers;enumdomgroups", additional_args="--timeout=10",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "rpcclient", "-U", "admin%Pass123", "-W", "CORP",
        "10.0.0.5", "-c", "enumdomusers;enumdomgroups", "--timeout=10",
    ]


def test_rpcclient_enum_handler_invocation_anonymous(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("rpcclient_enum")

    res = tool.handler(target="10.0.0.5")
    assert res["success"] is True
    assert captured["cmd"] == [
        "rpcclient", "-U", "", "10.0.0.5", "-c", "enumdomusers;enumdomgroups;querydominfo",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -k rpcclient -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="rpcclient_enum",
    category="network",
    description="RPC enumeration using rpcclient",
    endpoint="/api/tools/rpcclient"
)
def rpcclient_enum(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, commands: str = "enumdomusers;enumdomgroups;querydominfo", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["rpcclient"]
    if username and password:
        cmd.extend(["-U", f"{username}%{password}"])
    elif username:
        cmd.extend(["-U", username])
    else:
        cmd.extend(["-U", ""])
    if domain:
        cmd.extend(["-W", domain])
    cmd.extend([target, "-c", commands])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port rpcclient_enum to network tool registry

Uses rpcclient's native -c flag instead of the legacy echo-pipe, since
the new process manager executes commands as argv lists (no shell).
Same rpcclient commands run against the target either way.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 12: `smbmap_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `smbmap_scan(target, username=None, password=None, domain=None, additional_args=None)` registered as `"smbmap_scan"` at `/api/tools/smbmap`.

- [ ] **Step 1: Write the failing test**

```python
def test_smbmap_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("smbmap_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/smbmap"

    res = tool.handler(target="10.0.0.5", username="guest", password="pass", domain="WORKGROUP", additional_args="-R")
    assert res["success"] is True
    assert captured["cmd"] == ["smbmap", "-H", "10.0.0.5", "-u", "guest", "-p", "pass", "-d", "WORKGROUP", "-R"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_smbmap_scan_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="smbmap_scan",
    category="network",
    description="SMB share enumeration using SMBMap",
    endpoint="/api/tools/smbmap"
)
def smbmap_scan(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["smbmap", "-H", target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-d", domain])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port smbmap_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 13: `subfinder_enum`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `subfinder_enum(domain, silent=True, all_sources=False, additional_args=None)` registered as `"subfinder_enum"` at `/api/tools/subfinder`.

- [ ] **Step 1: Write the failing test**

```python
def test_subfinder_enum_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("subfinder_enum")
    assert tool is not None
    assert tool.endpoint == "/api/tools/subfinder"

    res = tool.handler(domain="example.com", silent=True, all_sources=True, additional_args="-timeout 30")
    assert res["success"] is True
    assert captured["cmd"] == ["subfinder", "-d", "example.com", "-silent", "-all", "-timeout", "30"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py::test_subfinder_enum_handler_invocation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="subfinder_enum",
    category="network",
    description="Passive subdomain enumeration using Subfinder",
    endpoint="/api/tools/subfinder"
)
def subfinder_enum(domain: str, silent: bool = True, all_sources: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    if all_sources:
        cmd.append("-all")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port subfinder_enum to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 14: `nmap_advanced_scan`

**Files:**
- Modify: `hexstrike/tools/network.py`
- Test: `tests/test_network_tools.py`

**Interfaces:**
- Produces: `nmap_advanced_scan(target, scan_type="-sS", ports=None, timing="T4", nse_scripts=None, os_detection=False, version_detection=False, aggressive=False, stealth=False, additional_args=None)` registered as `"nmap_advanced_scan"` at `/api/tools/nmap-advanced` — distinct from the existing `nmap_scan` (`/api/tools/nmap`).

- [ ] **Step 1: Write the failing test**

```python
def test_nmap_advanced_scan_handler_default_scripts(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nmap_advanced_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/nmap-advanced"

    res = tool.handler(
        target="10.0.0.5", ports="80,443", os_detection=True, version_detection=True, additional_args="--reason",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "nmap", "-sS", "10.0.0.5", "-p", "80,443", "-T4", "-O", "-sV",
        "--script=default,discovery,safe", "--reason",
    ]


def test_nmap_advanced_scan_handler_stealth_aggressive_custom_scripts(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nmap_advanced_scan")

    res = tool.handler(target="10.0.0.5", stealth=True, aggressive=True, nse_scripts="vuln")
    assert res["success"] is True
    assert captured["cmd"] == ["nmap", "-sS", "10.0.0.5", "-T2", "-f", "--mtu", "24", "-A", "--script=vuln"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -k nmap_advanced -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
@ToolRegistry.register(
    name="nmap_advanced_scan",
    category="network",
    description="Advanced Nmap scans with custom NSE scripts and optimized timing",
    endpoint="/api/tools/nmap-advanced"
)
def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: Optional[str] = None, timing: str = "T4", nse_scripts: Optional[str] = None, os_detection: bool = False, version_detection: bool = False, aggressive: bool = False, stealth: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nmap", scan_type, target]
    if ports:
        cmd.extend(["-p", ports])
    if stealth:
        cmd.extend(["-T2", "-f", "--mtu", "24"])
    else:
        cmd.append(f"-{timing}")
    if os_detection:
        cmd.append("-O")
    if version_detection:
        cmd.append("-sV")
    if aggressive:
        cmd.append("-A")
    if nse_scripts:
        cmd.append(f"--script={nse_scripts}")
    elif not aggressive:
        cmd.append("--script=default,discovery,safe")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/test_network_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hexstrike/tools/network.py tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
feat(tools): port nmap_advanced_scan to network tool registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```

---

### Task 15: Full verification

**Files:** none created/modified — verification only.

**Interfaces:**
- Consumes: `ToolRegistry.get_by_category("network")` from `hexstrike/core/registry.py`.

- [ ] **Step 1: Assert network category is complete**

```python
def test_network_category_has_16_tools():
    from hexstrike.core.registry import ToolRegistry
    import hexstrike.tools
    network_tools = ToolRegistry.get_by_category("network")
    assert len(network_tools) == 16
    names = {t.name for t in network_tools}
    assert names == {
        "nmap_scan", "rustscan_scan", "masscan_scan", "arp_scan", "autorecon_scan",
        "dnsenum_scan", "enum4linux_scan", "enum4linux_ng_scan", "fierce_scan",
        "nbtscan_scan", "netexec_scan", "responder_capture", "rpcclient_enum",
        "smbmap_scan", "subfinder_enum", "nmap_advanced_scan",
    }
```

Add this to `tests/test_network_tools.py`.

- [ ] **Step 2: Run the entire test suite**

Run: `./hexstrike-dev/bin/python3 -m pytest tests/ -v`
Expected: all tests PASS (the pre-existing 14 + the new network tests).

- [ ] **Step 3: Sanity-check the MCP layer picks up the new tools**

Run:
```bash
./hexstrike-dev/bin/python3 -c "
import asyncio
from hexstrike.mcp.client import HexStrikeClient
from hexstrike.mcp.server import setup_mcp_server

client = HexStrikeClient(server_url='http://127.0.0.1:8888')
mcp = setup_mcp_server(client)

async def main():
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert 'masscan_scan' in names
    assert 'rpcclient_enum' in names
    print('MCP tool count:', len(tools))

asyncio.run(main())
"
```
Expected: no assertion error, prints a tool count of at least 22 (8 original + 14 new).

- [ ] **Step 4: Commit**

```bash
git add tests/test_network_tools.py
git commit -m "$(cat <<'EOF'
test(tools): verify network category reaches full 16-tool parity

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011tdwwEqfxkQtyxjLc2PFaC
EOF
)"
```
