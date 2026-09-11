import os
import shutil
from typing import Dict, Any, List, Optional
from hexstrike.core.process import default_process_manager

def is_tool_available(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None

def resolve_binary(logical_name: str, candidates: List[str]) -> str:
    """Pick the binary name to invoke for a tool that goes by different names
    across distros/install methods (e.g. ProjectDiscovery's httpx is packaged
    as 'httpx-toolkit' on Kali since 'httpx' collides with python3-httpx).

    Checks the HEXSTRIKE_BIN_<LOGICAL_NAME> env var override first, then
    returns the first candidate found on PATH, then falls back to the first
    candidate so run_tool_command's own "not found" error still surfaces.
    """
    override = os.environ.get(f"HEXSTRIKE_BIN_{logical_name.upper()}")
    if override:
        return override
    for candidate in candidates:
        if is_tool_available(candidate):
            return candidate
    return candidates[0]

def run_tool_command(command: List[str], timeout: int = 300, use_cache: bool = True, stdin_input: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    tool_binary = command[0]
    check_path = tool_binary
    if cwd is not None and not os.path.isabs(tool_binary):
        check_path = os.path.join(cwd, tool_binary)
    if not is_tool_available(check_path):
        return {
            "success": False,
            "command": " ".join(command),
            "output": "",
            "error": f"Tool binary '{tool_binary}' not found on system PATH",
            "execution_time": "0.00s",
            "cached": False
        }
    return default_process_manager.execute_command(command, timeout=timeout, use_cache=use_cache, stdin_input=stdin_input, cwd=cwd)
