# HexStrike AI: Modular Architecture & Tool Registry Pattern Design Spec

- **Author**: Antigravity & User
- **Date**: 2026-09-08
- **Status**: Approved
- **Scope**: Architectural Refactoring & Modularization

---

## 1. Overview & Goals

HexStrike AI v6.0 currently bundles its entire API and MCP orchestration into two massive monolithic files:
- `hexstrike_server.py` (17,290 lines)
- `hexstrike_mcp.py` (5,471 lines)

While functionally rich (over 150 tools and multiple AI agents), this architecture poses maintainability, extensibility, and testability hurdles.

### Goals
1. **Package Modularization**: Refactor the codebase into a clean, idiomatic Python package (`hexstrike/`) with distinct layers for `core`, `tools`, `agents`, `api`, and `mcp`.
2. **Tool Registry Pattern**: Introduce a declarative `@ToolRegistry.register` pattern to register tools, their metadata, CLI parameters, and endpoints in category-specific modules.
3. **100% Backward Compatibility**: Keep `hexstrike_server.py` and `hexstrike_mcp.py` at the root as thin drop-in entrypoint wrappers so existing CLI commands (`python3 hexstrike_server.py --port 8888 --debug`) and MCP configuration files remain completely unbroken.
4. **Testability & Quality Assurance**: Provide automated unit tests using `pytest` to test the registry, process execution, caching, API factory, and health checks.

### Non-Goals
- Altering the command-line signatures, output formats, or behaviors of existing underlying security tools (e.g. Nmap, SQLMap, Gobuster).
- Changing external MCP client configurations or network protocols.

---

## 2. Directory & Module Structure

```text
hexstrike-ai/
├── hexstrike/                         # Core Python package
│   ├── __init__.py                    # Version (__version__ = "6.1.0-dev")
│   ├── core/                          # Low-level infrastructure & management
│   │   ├── __init__.py
│   │   ├── config.py                  # Server configuration, ports, timeouts, limits
│   │   ├── visual.py                  # Visual engine, ANSI colors, ASCII banners
│   │   ├── process.py                 # ProcessManager, caching, worker pool, sanitization
│   │   └── registry.py                # ToolRegistry & ToolSpec data structures
│   ├── tools/                         # Modular security tool implementations
│   │   ├── __init__.py                # Tool loader & registration trigger
│   │   ├── base.py                    # BaseTool helper & execution functions
│   │   ├── network.py                 # nmap, masscan, rustscan, responder, etc.
│   │   ├── web.py                     # gobuster, ffuf, nikto, sqlmap, nuclei, etc.
│   │   ├── binary.py                  # radare2, ghidra, gdb, pwntools, angr, etc.
│   │   ├── password.py                # hydra, john, hashcat, etc.
│   │   ├── osint.py                   # theharvester, amass, spiderfoot, etc.
│   │   ├── cloud.py                   # prowler, trivy, checkov, etc.
│   │   └── forensics.py               # binwalk, foremost, autopsy, etc.
│   ├── agents/                        # Autonomous AI agents
│   │   ├── __init__.py
│   │   ├── base_agent.py              # BaseAgent & decision engine logic
│   │   ├── bug_bounty.py              # BugBountyAgent
│   │   ├── ctf_solver.py              # CTFSolverAgent
│   │   └── exploit_generator.py       # AIExploitGenerator & CVE Intelligence
│   ├── api/                           # Flask REST API Layer
│   │   ├── __init__.py
│   │   ├── app.py                     # Flask application factory (create_app)
│   │   └── routes.py                  # System endpoints (/health, /api/status, /api/tools)
│   └── mcp/                           # MCP Protocol Layer
│       ├── __init__.py
│       ├── client.py                  # HexStrikeClient HTTP wrapper
│       └── server.py                  # FastMCP server dynamic bridge
├── hexstrike_server.py                # Backward-compatible CLI wrapper for API server
├── hexstrike_mcp.py                   # Backward-compatible CLI wrapper for MCP server
├── docs/superpowers/specs/            # Architecture specifications
└── tests/                             # Pytest test suite
    ├── __init__.py
    ├── test_registry.py               # Registry & ToolSpec tests
    ├── test_core.py                   # ProcessManager, caching, and config tests
    └── test_api.py                    # Flask API & health endpoint tests
```

---

## 3. Detailed Component Specifications

### 3.1 `hexstrike.core`
- **`config.py`**:
  - Contains all default constants: `API_PORT` (default: 8888), `DEFAULT_HOST` (0.0.0.0), `COMMAND_TIMEOUT` (300s), `CACHE_TTL` (3600s), `CACHE_SIZE` (1000).
  - Environment variable overrides (`HEXSTRIKE_PORT`, `HEXSTRIKE_TIMEOUT`, etc.).
- **`visual.py`**:
  - `ModernVisualEngine` with ANSI color definitions (`BLOOD_RED`, `MATRIX_GREEN`, `NEON_BLUE`, etc.).
  - `BANNER` text string matching the original styling.
  - Formatting helpers: `format_box()`, `format_status()`, `format_tool_execution()`.
- **`process.py`**:
  - `ProcessManager`:
    - Thread/Process pool worker initialization.
    - LRU Cache with TTL expiry for idempotent command executions.
    - Safe subprocess execution with timeout enforcement and stdout/stderr capture.
    - Input sanitization logic preventing unintended command injection while allowing valid CLI flags.
- **`registry.py`**:
  - `ToolSpec`:
    - `name`: str
    - `category`: str ("network", "web", "binary", etc.)
    - `description`: str
    - `endpoint`: str (e.g. `/api/tools/nmap`)
    - `handler`: Callable
    - `parameters`: Dict[str, Any] (JSON Schema for inputs)
    - `timeout`: int = 300
  - `ToolRegistry`:
    - `_tools`: Dict[str, ToolSpec]
    - `@classmethod register(name, category, description, endpoint=None, ...)` decorator.
    - `get(name)` -> ToolSpec
    - `get_all_tools()` -> List[ToolSpec]
    - `get_by_category(category)` -> List[ToolSpec]

### 3.2 `hexstrike.tools`
- **`base.py`**:
  - Common execution helpers using `ProcessManager.execute_command`.
  - Standardized JSON return format:
    ```json
    {
      "success": true,
      "command": "...",
      "output": "...",
      "execution_time": "...",
      "cached": false
    }
    ```
- **Category Modules (`network.py`, `web.py`, etc.)**:
  - Each module registers its relevant tools via `@ToolRegistry.register`.
  - Tool wrappers build safe CLI argument lists and invoke execution helpers.

### 3.3 `hexstrike.agents`
- **`base_agent.py`**:
  - Common autonomous decision engine, attack graph exploration, and tool selection AI.
- **Agent Modules (`bug_bounty.py`, `ctf_solver.py`, `exploit_generator.py`)**:
  - Encapsulates multi-step workflow logic (e.g. Subdomain enumeration -> Port scanning -> Web fingerprinting -> Vulnerability scanning).

### 3.4 `hexstrike.api`
- **`app.py`**:
  - `create_app(debug: bool = False, config_override: dict = None) -> Flask`:
    - Creates and configures Flask instance.
    - Registers system routes (`/health`, `/api/health`, `/api/tools`, `/api/telemetry`).
    - Dynamically binds each `ToolSpec` from `ToolRegistry.get_all_tools()` to a Flask view function mounted on `spec.endpoint`.
- **`routes.py`**:
  - Health check handler returning tools availability, system metrics, cache stats, and version (matching existing schema for complete client compatibility).

### 3.5 `hexstrike.mcp`
- **`client.py`**:
  - `HexStrikeClient`: HTTP communication client with retry logic, timeouts, and health checking.
- **`server.py`**:
  - `setup_mcp_server(client: HexStrikeClient) -> FastMCP`:
    - Registers all FastMCP tools dynamically mapping to the API endpoints or ToolRegistry specifications.
    - Maintains exact tool names and parameter schemas expected by LLM agents.

### 3.6 Backward-Compatible Entrypoints
- **`hexstrike_server.py`**:
  ```python
  #!/usr/bin/env python3
  import argparse
  from hexstrike.core.visual import BANNER, ModernVisualEngine
  from hexstrike.core.config import API_PORT
  from hexstrike.api.app import create_app

  if __name__ == "__main__":
      print(BANNER)
      parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
      parser.add_argument("--debug", action="store_true", help="Enable debug mode")
      parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
      args = parser.parse_args()

      app = create_app(debug=args.debug)
      app.run(host="0.0.0.0", port=args.port, debug=args.debug)
  ```
- **`hexstrike_mcp.py`**:
  ```python
  #!/usr/bin/env python3
  from hexstrike.mcp.server import main

  if __name__ == "__main__":
      main()
  ```

---

## 4. Testing & Verification Plan

1. **Unit Testing (`pytest`)**:
   - `test_registry.py`: Test tool registration, retrieval by name/category, duplicate prevention.
   - `test_core.py`: Test `ProcessManager` caching, command timeout, and input sanitization.
   - `test_api.py`: Test Flask `create_app()`, `/health` JSON structure, and tool endpoint invocation with mocks.
2. **Integration & Smoke Verification**:
   - Start the refactored server with `python3 hexstrike_server.py --port 8888 --debug`.
   - Send HTTP request to `http://127.0.0.1:8888/health` and verify `status: "healthy"` and `all_essential_tools_available: true`.
   - Verify `python3 hexstrike_mcp.py --help` runs without error.
   - Verify existing Tmux session / window workflow continues to function flawlessly.
