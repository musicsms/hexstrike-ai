import os
import shutil
from typing import Dict, Any, List, Optional
from hexstrike.core.process import default_process_manager

def is_tool_available(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None

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
