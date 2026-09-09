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
