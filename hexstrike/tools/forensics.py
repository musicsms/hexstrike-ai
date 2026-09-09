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
