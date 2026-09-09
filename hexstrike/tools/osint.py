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
