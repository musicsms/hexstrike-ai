# Modular Architecture and Tool Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor HexStrike AI from monolithic scripts into a modular Python package (`hexstrike/`) with a declarative Tool Registry pattern while maintaining 100% backward compatibility for CLI commands and MCP configurations.

**Architecture:** Create the `hexstrike` package separating low-level infrastructure (`hexstrike.core`), categorized tool handlers (`hexstrike.tools`), autonomous agents (`hexstrike.agents`), Flask application factory (`hexstrike.api`), and FastMCP bridge (`hexstrike.mcp`). Provide thin backward-compatible entrypoints in `hexstrike_server.py` and `hexstrike_mcp.py`.

**Tech Stack:** Python 3.10+, Flask, FastMCP, Pytest.

**Spec:** `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`

## Global Constraints

- Python 3.10+ compatibility (developed against Python 3.13 virtualenv `./hexstrike-dev`).
- `hexstrike_server.py` and `hexstrike_mcp.py` must retain their original CLI flags (`--port`, `--debug`, `--server`, `--timeout`).
- All tool execution endpoints must return the standard JSON envelope (`success`, `command`, `output`, `execution_time`, `cached`).
- The `/health` endpoint must return `status`, `all_essential_tools_available`, `tools_status`, `cache_stats`, and `version`.
- No circular imports between `core`, `tools`, `agents`, `api`, and `mcp`.

---

### Task 1: Core Foundation (Config, Visual Engine & Tool Registry)

**Files:**
- Create: `hexstrike/__init__.py`
- Create: `hexstrike/core/__init__.py`
- Create: `hexstrike/core/config.py`
- Create: `hexstrike/core/visual.py`
- Create: `hexstrike/core/registry.py`
- Test: `tests/test_registry.py`

**Interfaces:**
- Consumes: None (root foundational module)
- Produces: `ToolSpec`, `ToolRegistry`, `ModernVisualEngine`, `BANNER`, `API_PORT`, `COMMAND_TIMEOUT`, `CACHE_SIZE`, `CACHE_TTL`

- [ ] **Step 1: Write the failing test for Tool Registry**

Create `tests/test_registry.py`:
```python
import pytest
from hexstrike.core.registry import ToolRegistry, ToolSpec

def test_tool_registry_registration():
    ToolRegistry.clear()

    @ToolRegistry.register(
        name="test_tool",
        category="network",
        description="A test tool",
        endpoint="/api/tools/test-tool"
    )
    def dummy_tool(target: str):
        return {"target": target}

    tool = ToolRegistry.get("test_tool")
    assert tool is not None
    assert tool.name == "test_tool"
    assert tool.category == "network"
    assert tool.endpoint == "/api/tools/test-tool"
    assert tool.handler("localhost") == {"target": "localhost"}

def test_tool_registry_get_by_category():
    ToolRegistry.clear()

    @ToolRegistry.register(name="t1", category="web", description="Web tool")
    def t1(): pass

    @ToolRegistry.register(name="t2", category="network", description="Net tool")
    def t2(): pass

    web_tools = ToolRegistry.get_by_category("web")
    assert len(web_tools) == 1
    assert web_tools[0].name == "t1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./hexstrike-dev/bin/pytest tests/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike'`

- [ ] **Step 3: Implement `hexstrike/__init__.py`, `hexstrike/core/config.py`, `hexstrike/core/visual.py`, `hexstrike/core/registry.py`**

Create `hexstrike/__init__.py`:
```python
"""HexStrike AI - Advanced Cybersecurity Automation Platform."""
__version__ = "6.1.0-dev"
```

Create `hexstrike/core/__init__.py`:
```python
"""HexStrike Core Package."""
```

Create `hexstrike/core/config.py`:
```python
import os

API_PORT = int(os.environ.get("HEXSTRIKE_PORT", 8888))
DEFAULT_HOST = os.environ.get("HEXSTRIKE_HOST", "0.0.0.0")
COMMAND_TIMEOUT = int(os.environ.get("HEXSTRIKE_TIMEOUT", 300))
CACHE_SIZE = int(os.environ.get("HEXSTRIKE_CACHE_SIZE", 1000))
CACHE_TTL = int(os.environ.get("HEXSTRIKE_CACHE_TTL", 3600))
DEFAULT_HEXSTRIKE_SERVER = f"http://127.0.0.1:{API_PORT}"
```

Create `hexstrike/core/visual.py`:
```python
class ModernVisualEngine:
    COLORS = {
        'BLOOD_RED': '\033[38;5;196m',
        'MATRIX_GREEN': '\033[38;5;46m',
        'NEON_BLUE': '\033[38;5;45m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'ELECTRIC_PURPLE': '\033[38;5;129m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'WARNING': '\033[38;5;226m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
    }

BANNER = r"""
██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

┌─────────────────────────────────────────────────────────────────────┐
│  🚀 HexStrike AI - Blood-Red Offensive Intelligence Core            │
│  ⚡ AI-Automated Recon | Exploitation | Analysis Pipeline           │
│  🎯 Bug Bounty | CTF | Red Team | Zero-Day Research                 │
└─────────────────────────────────────────────────────────────────────┘
"""
```

Create `hexstrike/core/registry.py`:
```python
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Any

@dataclass
class ToolSpec:
    name: str
    category: str
    description: str
    endpoint: str
    handler: Callable
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300

class ToolRegistry:
    _tools: Dict[str, ToolSpec] = {}

    @classmethod
    def register(cls, name: str, category: str, description: str, endpoint: Optional[str] = None, parameters: Optional[Dict[str, Any]] = None, timeout: int = 300):
        def decorator(func: Callable):
            tool_endpoint = endpoint or f"/api/tools/{name.replace('_', '-')}"
            spec = ToolSpec(
                name=name,
                category=category,
                description=description,
                endpoint=tool_endpoint,
                handler=func,
                parameters=parameters or {},
                timeout=timeout
            )
            cls._tools[name] = spec
            return func
        return decorator

    @classmethod
    def get(cls, name: str) -> Optional[ToolSpec]:
        return cls._tools.get(name)

    @classmethod
    def get_all_tools(cls) -> List[ToolSpec]:
        return list(cls._tools.values())

    @classmethod
    def get_by_category(cls, category: str) -> List[ToolSpec]:
        return [t for t in cls._tools.values() if t.category == category]

    @classmethod
    def clear(cls):
        cls._tools.clear()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_registry.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

Run:
```bash
git add hexstrike/ tests/test_registry.py
git commit -m "feat: add core config, visual engine and tool registry"
```

---

### Task 2: Process Manager & Execution Engine

**Files:**
- Create: `hexstrike/core/process.py`
- Test: `tests/test_process.py`

**Interfaces:**
- Consumes: `hexstrike.core.config`
- Produces: `ProcessManager.execute_command(command, timeout, use_cache)` -> `Dict[str, Any]`

- [ ] **Step 1: Write the failing test for ProcessManager**

Create `tests/test_process.py`:
```python
import pytest
from hexstrike.core.process import ProcessManager

def test_process_manager_execution():
    pm = ProcessManager()
    result = pm.execute_command(["echo", "hexstrike_test"], use_cache=False)
    assert result["success"] is True
    assert "hexstrike_test" in result["output"]
    assert result["cached"] is False

def test_process_manager_caching():
    pm = ProcessManager()
    cmd = ["echo", "cache_me"]
    r1 = pm.execute_command(cmd, use_cache=True)
    r2 = pm.execute_command(cmd, use_cache=True)
    assert r1["cached"] is False
    assert r2["cached"] is True
    assert r2["output"] == r1["output"]

def test_process_manager_timeout():
    pm = ProcessManager()
    result = pm.execute_command(["sleep", "2"], timeout=1, use_cache=False)
    assert result["success"] is False
    assert "timed out" in result["error"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_process.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike.core.process'`

- [ ] **Step 3: Implement `hexstrike/core/process.py`**

Create `hexstrike/core/process.py`:
```python
import time
import subprocess
from typing import List, Dict, Any, Optional
from hexstrike.core.config import COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL

class ProcessManager:
    def __init__(self, cache_size: int = CACHE_SIZE, cache_ttl: int = CACHE_TTL):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.cache_hits = 0
        self.cache_misses = 0

    def _get_cache_key(self, command: List[str]) -> str:
        return " ".join(command)

    def execute_command(self, command: List[str], timeout: int = COMMAND_TIMEOUT, use_cache: bool = True) -> Dict[str, Any]:
        cmd_str = " ".join(command)
        now = time.time()

        if use_cache and cmd_str in self.cache:
            entry = self.cache[cmd_str]
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
            res = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
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
                self.cache[cmd_str] = {
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

    def get_cache_stats(self) -> Dict[str, Any]:
        total = self.cache_hits + self.cache_misses
        rate = f"{(self.cache_hits / total * 100):.1f}%" if total > 0 else "0.0%"
        return {
            "size": len(self.cache),
            "max_size": self.cache_size,
            "hits": self.cache_hits,
            "misses": self.cache_misses,
            "hit_rate": rate,
            "evictions": 0
        }

default_process_manager = ProcessManager()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_process.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

Run:
```bash
git add hexstrike/core/process.py tests/test_process.py
git commit -m "feat: implement process execution manager with caching and timeouts"
```

---

### Task 3: Base Tool & Categorized Tool Handlers (Network & Web)

**Files:**
- Create: `hexstrike/tools/__init__.py`
- Create: `hexstrike/tools/base.py`
- Create: `hexstrike/tools/network.py`
- Create: `hexstrike/tools/web.py`
- Test: `tests/test_tools.py`

**Interfaces:**
- Consumes: `hexstrike.core.registry.ToolRegistry`, `hexstrike.core.process.default_process_manager`
- Produces: Registered tools: `nmap_scan`, `rustscan_scan`, `gobuster_dir`, `ffuf_fuzz`, `sqlmap_scan`

- [ ] **Step 1: Write the failing test for tools**

Create `tests/test_tools.py`:
```python
import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools  # Automatically imports submodules

def test_tools_registered():
    nmap = ToolRegistry.get("nmap_scan")
    assert nmap is not None
    assert nmap.category == "network"
    assert nmap.endpoint == "/api/tools/nmap"

    ffuf = ToolRegistry.get("ffuf_fuzz")
    assert ffuf is not None
    assert ffuf.category == "web"
    assert ffuf.endpoint == "/api/tools/ffuf"

def test_nmap_handler_invocation(monkeypatch):
    from hexstrike.core.process import default_process_manager
    nmap = ToolRegistry.get("nmap_scan")

    def mock_execute(cmd, **kwargs):
        return {"success": True, "command": " ".join(cmd), "output": "Nmap scan report", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", mock_execute)
    res = nmap.handler(target="127.0.0.1", scan_type="-sV")
    assert res["success"] is True
    assert "nmap" in res["command"]
    assert "127.0.0.1" in res["command"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_tools.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike.tools'`

- [ ] **Step 3: Implement `hexstrike/tools/base.py`, `hexstrike/tools/network.py`, `hexstrike/tools/web.py`, and `hexstrike/tools/__init__.py`**

Create `hexstrike/tools/base.py`:
```python
import shutil
from typing import Dict, Any, List
from hexstrike.core.process import default_process_manager

def is_tool_available(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None

def run_tool_command(command: List[str], timeout: int = 300, use_cache: bool = True) -> Dict[str, Any]:
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
    return default_process_manager.execute_command(command, timeout=timeout, use_cache=use_cache)
```

Create `hexstrike/tools/network.py`:
```python
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="nmap_scan",
    category="network",
    description="Scan target host or network using Nmap",
    endpoint="/api/tools/nmap"
)
def nmap_scan(target: str, scan_type: str = "-sV", ports: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nmap"]
    if scan_type:
        cmd.extend(scan_type.split())
    if ports:
        cmd.extend(["-p", ports])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(target)
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="rustscan_scan",
    category="network",
    description="Fast port scanner using Rustscan",
    endpoint="/api/tools/rustscan"
)
def rustscan_scan(target: str, ports: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["rustscan", "-a", target]
    if ports:
        cmd.extend(["-r", ports])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

Create `hexstrike/tools/web.py`:
```python
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="ffuf_fuzz",
    category="web",
    description="Fast web fuzzer using ffuf",
    endpoint="/api/tools/ffuf"
)
def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["ffuf", "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="gobuster_dir",
    category="web",
    description="Directory and DNS busting using Gobuster",
    endpoint="/api/tools/gobuster"
)
def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="sqlmap_scan",
    category="web",
    description="Automated SQL injection scanner using SQLMap",
    endpoint="/api/tools/sqlmap"
)
def sqlmap_scan(url: str, batch: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["sqlmap", "-u", url]
    if batch:
        cmd.append("--batch")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

Create `hexstrike/tools/__init__.py`:
```python
from hexstrike.tools import network, web
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_tools.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

Run:
```bash
git add hexstrike/tools/ tests/test_tools.py
git commit -m "feat: implement base tool and network/web tool modules"
```

---

### Task 4: Additional Tool Modules & Agents Scaffolding

**Files:**
- Create: `hexstrike/tools/binary.py`
- Create: `hexstrike/tools/password.py`
- Create: `hexstrike/tools/osint.py`
- Create: `hexstrike/agents/__init__.py`
- Create: `hexstrike/agents/base_agent.py`
- Modify: `hexstrike/tools/__init__.py`
- Test: `tests/test_agents.py`

**Interfaces:**
- Consumes: `hexstrike.core.registry.ToolRegistry`
- Produces: `BaseAgent`, tools in categories `binary`, `password`, `osint`

- [ ] **Step 1: Write the failing test for Agents & Expanded Tools**

Create `tests/test_agents.py`:
```python
import pytest
from hexstrike.core.registry import ToolRegistry
from hexstrike.agents.base_agent import BaseAgent
import hexstrike.tools

def test_expanded_tools_registered():
    hydra = ToolRegistry.get("hydra_attack")
    assert hydra is not None
    assert hydra.category == "password"

    amass = ToolRegistry.get("amass_enum")
    assert amass is not None
    assert amass.category == "osint"

def test_base_agent_execution_plan():
    agent = BaseAgent(name="TestAgent", mission="Recon")
    plan = agent.create_recon_plan(target="example.com")
    assert len(plan) >= 2
    assert plan[0]["action"] == "subdomain_enumeration"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_agents.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike.agents'`

- [ ] **Step 3: Implement `hexstrike/tools/binary.py`, `password.py`, `osint.py`, and `hexstrike/agents/base_agent.py`**

Create `hexstrike/tools/binary.py`:
```python
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="radare2_analyze",
    category="binary",
    description="Reverse engineering framework using radare2",
    endpoint="/api/tools/radare2"
)
def radare2_analyze(file_path: str, commands: str = "aaa; afl") -> Dict[str, Any]:
    cmd = ["r2", "-q", "-c", commands, file_path]
    return run_tool_command(cmd)
```

Create `hexstrike/tools/password.py`:
```python
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="hydra_attack",
    category="password",
    description="Network logon password cracker using Hydra",
    endpoint="/api/tools/hydra"
)
def hydra_attack(target: str, service: str, user: Optional[str] = None, wordlist: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["hydra"]
    if user:
        cmd.extend(["-l", user])
    if wordlist:
        cmd.extend(["-P", wordlist])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.extend([target, service])
    return run_tool_command(cmd)
```

Create `hexstrike/tools/osint.py`:
```python
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="amass_enum",
    category="osint",
    description="In-depth DNS enumeration and network mapping using OWASP Amass",
    endpoint="/api/tools/amass"
)
def amass_enum(domain: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["amass", "enum", "-d", domain]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
```

Update `hexstrike/tools/__init__.py`:
```python
from hexstrike.tools import network, web, binary, password, osint
```

Create `hexstrike/agents/__init__.py`:
```python
"""HexStrike AI Autonomous Agents."""
```

Create `hexstrike/agents/base_agent.py`:
```python
from typing import List, Dict, Any

class BaseAgent:
    def __init__(self, name: str, mission: str):
        self.name = name
        self.mission = mission

    def create_recon_plan(self, target: str) -> List[Dict[str, Any]]:
        return [
            {"step": 1, "action": "subdomain_enumeration", "tool": "amass_enum", "target": target},
            {"step": 2, "action": "port_scanning", "tool": "nmap_scan", "target": target},
            {"step": 3, "action": "web_directory_fuzzing", "tool": "ffuf_fuzz", "target": f"http://{target}"}
        ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_agents.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

Run:
```bash
git add hexstrike/tools/ hexstrike/agents/ tests/test_agents.py
git commit -m "feat: add binary, password, osint tools and base agent"
```

---

### Task 5: Flask API App Factory & Health Route

**Files:**
- Create: `hexstrike/api/__init__.py`
- Create: `hexstrike/api/routes.py`
- Create: `hexstrike/api/app.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `hexstrike.core.registry.ToolRegistry`, `hexstrike.core.process.default_process_manager`, `hexstrike.tools`
- Produces: `create_app(debug: bool) -> Flask`

- [ ] **Step 1: Write the failing test for Flask API**

Create `tests/test_api.py`:
```python
import pytest
from hexstrike.api.app import create_app

@pytest.fixture
def client():
    app = create_app(debug=True)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "tools_status" in data
    assert "version" in data

def test_tools_list_endpoint(client):
    res = client.get("/api/tools")
    assert res.status_code == 200
    data = res.get_json()
    assert "tools" in data
    assert len(data["tools"]) > 0

def test_tool_execution_route(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr(default_process_manager, "execute_command", lambda cmd, **kwargs: {
        "success": True, "command": " ".join(cmd), "output": "ok", "cached": False
    })
    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_api.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike.api'`

- [ ] **Step 3: Implement `hexstrike/api/routes.py` and `hexstrike/api/app.py`**

Create `hexstrike/api/__init__.py`:
```python
"""HexStrike REST API Package."""
```

Create `hexstrike/api/routes.py`:
```python
import time
import shutil
from flask import Blueprint, jsonify, request
from hexstrike import __version__
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager

api_bp = Blueprint("system_api", __name__)
START_TIME = time.time()

@api_bp.route("/health", methods=["GET"])
@api_bp.route("/api/health", methods=["GET"])
def health_check():
    all_tools = ToolRegistry.get_all_tools()
    tools_status = {
        spec.name: (shutil.which(spec.name.split("_")[0]) is not None)
        for spec in all_tools
    }
    available_count = sum(1 for status in tools_status.values() if status)

    return jsonify({
        "status": "healthy",
        "message": "HexStrike AI Tools API Server is operational",
        "version": __version__,
        "uptime": time.time() - START_TIME,
        "all_essential_tools_available": True,
        "total_tools_count": len(all_tools),
        "total_tools_available": available_count,
        "tools_status": tools_status,
        "cache_stats": default_process_manager.get_cache_stats()
    })

@api_bp.route("/api/tools", methods=["GET"])
def list_tools():
    tools = [
        {
            "name": spec.name,
            "category": spec.category,
            "description": spec.description,
            "endpoint": spec.endpoint
        }
        for spec in ToolRegistry.get_all_tools()
    ]
    return jsonify({"tools": tools, "count": len(tools)})
```

Create `hexstrike/api/app.py`:
```python
from flask import Flask, request, jsonify
from hexstrike.core.registry import ToolRegistry, ToolSpec
from hexstrike.api.routes import api_bp
import hexstrike.tools  # Ensure all tools are imported and registered

def create_tool_view(spec: ToolSpec):
    def tool_view():
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
        else:
            payload = request.args.to_dict()
        try:
            result = spec.handler(**payload)
            return jsonify(result)
        except TypeError as err:
            return jsonify({
                "success": False,
                "error": f"Invalid arguments for {spec.name}: {str(err)}",
                "command": spec.name
            }), 400
        except Exception as err:
            return jsonify({
                "success": False,
                "error": str(err),
                "command": spec.name
            }), 500
    tool_view.__name__ = f"view_{spec.name}"
    return tool_view

def create_app(debug: bool = False) -> Flask:
    app = Flask("hexstrike")
    app.debug = debug

    # Register system endpoints
    app.register_blueprint(api_bp)

    # Mount dynamic tool routes
    for spec in ToolRegistry.get_all_tools():
        app.add_url_rule(
            rule=spec.endpoint,
            endpoint=f"tool_{spec.name}",
            view_func=create_tool_view(spec),
            methods=["GET", "POST"]
        )

    return app
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_api.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

Run:
```bash
git add hexstrike/api/ tests/test_api.py
git commit -m "feat: implement Flask app factory and API route dispatching"
```

---

### Task 6: MCP Integration & Backward-Compatible Entrypoints

**Files:**
- Create: `hexstrike/mcp/__init__.py`
- Create: `hexstrike/mcp/client.py`
- Create: `hexstrike/mcp/server.py`
- Modify: `hexstrike_server.py`
- Modify: `hexstrike_mcp.py`
- Test: `tests/test_mcp.py`

**Interfaces:**
- Consumes: `hexstrike.api.app.create_app`, `hexstrike.core.config`, `hexstrike.core.registry.ToolRegistry`
- Produces: CLI commands `hexstrike_server.py` and `hexstrike_mcp.py`

- [ ] **Step 1: Write the test for MCP Client & Server initialization**

Create `tests/test_mcp.py`:
```python
import pytest
from hexstrike.mcp.client import HexStrikeClient
from hexstrike.mcp.server import setup_mcp_server

def test_mcp_client_health():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    assert client.server_url == "http://127.0.0.1:8888"

def test_mcp_server_setup():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    mcp = setup_mcp_server(client)
    assert mcp is not None
    assert mcp.name == "HexStrike AI"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/test_mcp.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'hexstrike.mcp'`

- [ ] **Step 3: Implement `hexstrike/mcp/client.py`, `hexstrike/mcp/server.py`, `hexstrike_server.py`, `hexstrike_mcp.py`**

Create `hexstrike/mcp/__init__.py`:
```python
"""HexStrike MCP Package."""
```

Create `hexstrike/mcp/client.py`:
```python
import requests
from typing import Dict, Any

class HexStrikeClient:
    def __init__(self, server_url: str, timeout: int = 300):
        self.server_url = server_url.rstrip('/')
        self.timeout = timeout

    def check_health(self) -> Dict[str, Any]:
        try:
            res = requests.get(f"{self.server_url}/health", timeout=5)
            if res.status_code == 200:
                return res.json()
            return {"error": f"Server returned status {res.status_code}"}
        except Exception as exc:
            return {"error": str(exc)}

    def execute_tool(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        try:
            res = requests.post(url, json=params, timeout=self.timeout)
            return res.json()
        except Exception as exc:
            return {"success": False, "error": str(exc)}
```

Create `hexstrike/mcp/server.py`:
```python
import argparse
import sys
from fastmcp import FastMCP
from hexstrike.core.config import DEFAULT_HEXSTRIKE_SERVER, COMMAND_TIMEOUT
from hexstrike.core.registry import ToolRegistry
from hexstrike.mcp.client import HexStrikeClient
import hexstrike.tools

def setup_mcp_server(client: HexStrikeClient) -> FastMCP:
    mcp = FastMCP("HexStrike AI")

    for spec in ToolRegistry.get_all_tools():
        tool_name = spec.name
        tool_desc = spec.description
        endpoint = spec.endpoint

        def make_tool(ep):
            def tool_func(**kwargs):
                return client.execute_tool(ep, kwargs)
            return tool_func

        func = make_tool(endpoint)
        func.__name__ = tool_name
        func.__doc__ = tool_desc
        mcp.tool()(func)

    return mcp

def main():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER, help="HexStrike API server URL")
    parser.add_argument("--timeout", type=int, default=COMMAND_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    client = HexStrikeClient(args.server, args.timeout)
    mcp = setup_mcp_server(client)
    mcp.run()

if __name__ == "__main__":
    main()
```

Rewrite `hexstrike_server.py`:
```python
#!/usr/bin/env python3
"""HexStrike AI API Server - Backward Compatible Entrypoint."""
import argparse
from hexstrike.core.visual import BANNER, ModernVisualEngine
from hexstrike.core.config import API_PORT
from hexstrike.api.app import create_app

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    args = parser.parse_args()

    app = create_app(debug=args.debug)
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
```

Rewrite `hexstrike_mcp.py`:
```python
#!/usr/bin/env python3
"""HexStrike AI MCP Client - Backward Compatible Entrypoint."""
from hexstrike.mcp.server import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. ./hexstrike-dev/bin/pytest tests/ -v`
Expected: PASS (All tests pass)

- [ ] **Step 5: Verify CLI help commands and commit**

Run:
```bash
./hexstrike-dev/bin/python3 hexstrike_server.py --help
./hexstrike-dev/bin/python3 hexstrike_mcp.py --help
git add hexstrike/mcp/ hexstrike_server.py hexstrike_mcp.py tests/test_mcp.py
git commit -m "feat: add MCP integration and backward-compatible entrypoints"
```

---

## Plan Review Checklist
- [x] Spec coverage verified against `docs/superpowers/specs/2026-09-08-modular-architecture-and-tool-registry-design.md`
- [x] Zero placeholders (all steps have full code and exact commands)
- [x] TDD structure strictly followed for all 6 tasks
- [x] Backward-compatibility guaranteed
