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
