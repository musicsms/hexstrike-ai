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
