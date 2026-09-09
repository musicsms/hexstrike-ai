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

@ToolRegistry.register(
    name="arp_scan",
    category="network",
    description="Network discovery using arp-scan",
    endpoint="/api/tools/arp-scan"
)
def arp_scan(target: Optional[str] = None, interface: Optional[str] = None, local_network: bool = False, timeout: int = 500, retry: int = 3, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["arp-scan", "-t", str(timeout), "-r", str(retry)]
    if interface:
        cmd.extend(["-I", interface])
    if local_network:
        cmd.append("-l")
    else:
        cmd.append(target)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="autorecon_scan",
    category="network",
    description="Comprehensive automated reconnaissance using AutoRecon",
    endpoint="/api/tools/autorecon"
)
def autorecon_scan(target: str, output_dir: str = "/tmp/autorecon", port_scans: str = "top-100-ports", service_scans: str = "default", heartbeat: int = 60, timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["autorecon", target, "-o", output_dir, "--heartbeat", str(heartbeat), "--timeout", str(timeout)]
    # Preserves original quirk: default ("top-100-ports") differs from the "default" sentinel,
    # so --port-scans is emitted unless the caller explicitly passes "default".
    if port_scans != "default":
        cmd.extend(["--port-scans", port_scans])
    if service_scans != "default":
        cmd.extend(["--service-scans", service_scans])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dnsenum_scan",
    category="network",
    description="DNS enumeration using dnsenum",
    endpoint="/api/tools/dnsenum"
)
def dnsenum_scan(domain: str, dns_server: Optional[str] = None, wordlist: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dnsenum", domain]
    if dns_server:
        cmd.extend(["--dnsserver", dns_server])
    if wordlist:
        cmd.extend(["--file", wordlist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="enum4linux_scan",
    category="network",
    description="SMB/Windows enumeration using enum4linux",
    endpoint="/api/tools/enum4linux"
)
def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
    cmd = ["enum4linux"] + additional_args.split() + [target]
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="enum4linux_ng_scan",
    category="network",
    description="Advanced SMB enumeration using enum4linux-ng",
    endpoint="/api/tools/enum4linux-ng"
)
def enum4linux_ng_scan(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, shares: bool = True, users: bool = True, groups: bool = True, policy: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["enum4linux-ng", target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-d", domain])
    enum_options = []
    if shares:
        enum_options.append("S")
    if users:
        enum_options.append("U")
    if groups:
        enum_options.append("G")
    if policy:
        enum_options.append("P")
    if enum_options:
        cmd.extend(["-A", ",".join(enum_options)])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="fierce_scan",
    category="network",
    description="DNS reconnaissance using fierce",
    endpoint="/api/tools/fierce"
)
def fierce_scan(domain: str, dns_server: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["fierce", "--domain", domain]
    if dns_server:
        cmd.extend(["--dns-servers", dns_server])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="nbtscan_scan",
    category="network",
    description="NetBIOS name scanning using nbtscan",
    endpoint="/api/tools/nbtscan"
)
def nbtscan_scan(target: str, verbose: bool = False, timeout: int = 2, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nbtscan", "-t", str(timeout)]
    if verbose:
        cmd.append("-v")
    cmd.append(target)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="netexec_scan",
    category="network",
    description="Network service exploitation using NetExec (formerly CrackMapExec)",
    endpoint="/api/tools/netexec"
)
def netexec_scan(target: str, protocol: str = "smb", username: Optional[str] = None, password: Optional[str] = None, hash: Optional[str] = None, module: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nxc", protocol, target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if hash:
        cmd.extend(["-H", hash])
    if module:
        cmd.extend(["-M", module])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="responder_capture",
    category="network",
    description="LLMNR/NBT-NS/mDNS poisoner and credential harvester using Responder",
    endpoint="/api/tools/responder"
)
def responder_capture(interface: str = "eth0", analyze: bool = False, wpad: bool = True, force_wpad_auth: bool = False, fingerprint: bool = False, duration: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["timeout", str(duration), "responder", "-I", interface]
    if analyze:
        cmd.append("-A")
    if wpad:
        cmd.append("-w")
    if force_wpad_auth:
        cmd.append("-F")
    if fingerprint:
        cmd.append("-f")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="rpcclient_enum",
    category="network",
    description="RPC enumeration using rpcclient",
    endpoint="/api/tools/rpcclient"
)
def rpcclient_enum(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, commands: str = "enumdomusers;enumdomgroups;querydominfo", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["rpcclient"]
    if username and password:
        cmd.extend(["-U", f"{username}%{password}"])
    elif username:
        cmd.extend(["-U", username])
    else:
        cmd.extend(["-U", ""])
    if domain:
        cmd.extend(["-W", domain])
    cmd.extend([target, "-c", commands])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="smbmap_scan",
    category="network",
    description="SMB share enumeration using SMBMap",
    endpoint="/api/tools/smbmap"
)
def smbmap_scan(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["smbmap", "-H", target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-d", domain])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
