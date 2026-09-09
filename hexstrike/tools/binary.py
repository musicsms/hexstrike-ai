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
