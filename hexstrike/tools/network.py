from typing import Dict, Any, Optional, Annotated
from pydantic import Field
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="nmap_scan",
    category="network",
    description="Scan target host or network using Nmap - most accurate service/OS detection; slower than rustscan_scan/masscan_scan on large port ranges",
    endpoint="/api/tools/nmap"
)
def nmap_scan(
    target: str,
    scan_type: Annotated[str, Field(description="Raw Nmap scan flag(s), e.g. '-sV' (version detection), '-sS' (SYN stealth), '-sT' (TCP connect), '-sU' (UDP)")] = "-sV",
    ports: Optional[str] = None,
    timeout: int = 300,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["nmap"]
    if scan_type:
        cmd.extend(scan_type.split())
    if ports:
        cmd.extend(["-p", ports])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(target)
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="rustscan_scan",
    category="network",
    description="Fast port scanner using Rustscan - quick initial port discovery, pair with nmap_scan for service detection",
    endpoint="/api/tools/rustscan"
)
def rustscan_scan(target: str, ports: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["rustscan", "-a", target]
    if ports:
        # rustscan takes a comma list via -p ("80,443") or a start-end range via -r ("1-1000");
        # the two formats are mutually exclusive and each errors on the other's syntax.
        if "," not in ports and "-" in ports:
            cmd.extend(["-r", ports])
        else:
            cmd.extend(["-p", ports])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="masscan_scan",
    category="network",
    description="High-speed Internet-scale port scanner using Masscan - fastest option for huge ranges, less accurate than nmap_scan",
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
    description="SMB/Windows enumeration using enum4linux - classic broad enumeration (users, shares, policy); prefer enum4linux_ng_scan for a more reliable modern rewrite",
    endpoint="/api/tools/enum4linux"
)
def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
    cmd = ["enum4linux"] + additional_args.split() + [target]
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="enum4linux_ng_scan",
    category="network",
    description="Advanced SMB enumeration using enum4linux-ng - actively maintained rewrite of enum4linux with more reliable output",
    endpoint="/api/tools/enum4linux-ng"
)
def enum4linux_ng_scan(target: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, shares: bool = True, users: bool = True, groups: bool = True, policy: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["enum4linux-ng", target]
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if domain:
        cmd.extend(["-w", domain])
    if shares:
        cmd.append("-S")
    if users:
        cmd.append("-U")
    if groups:
        cmd.append("-G")
    if policy:
        cmd.append("-P")
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
    description="NetBIOS name scanning using nbtscan - network-range host discovery, not a full enumeration tool",
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
def netexec_scan(
    target: str,
    protocol: Annotated[str, Field(description="Target service protocol, e.g. 'smb', 'winrm', 'ssh', 'ldap', 'rdp'")] = "smb",
    username: Optional[str] = None,
    password: Optional[str] = None,
    hash: Annotated[Optional[str], Field(description="NTLM hash for pass-the-hash auth, format 'LM:NT' or just the NT hash, used instead of password")] = None,
    module: Annotated[Optional[str], Field(description="NetExec module name to run against the target, e.g. 'mimikatz', 'lsassy'")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
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
    # Note: current Responder builds (lgandx/Responder) removed -f/--fingerprint;
    # passing it makes Responder exit with "no such option: -f", so it's a no-op here.
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="rpcclient_enum",
    category="network",
    description="RPC enumeration using rpcclient - low-level, scriptable RPC calls for targeted manual enumeration",
    endpoint="/api/tools/rpcclient"
)
def rpcclient_enum(
    target: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    commands: Annotated[str, Field(description="Semicolon-separated rpcclient commands to run, e.g. 'enumdomusers;enumdomgroups;querydominfo'")] = "enumdomusers;enumdomgroups;querydominfo",
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
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
    description="SMB share enumeration using SMBMap - focused specifically on share access/permissions rather than full domain enumeration",
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

@ToolRegistry.register(
    name="subfinder_enum",
    category="network",
    description="Passive subdomain enumeration using Subfinder - fast, low-noise, good first pass before a deeper scan with amass_enum",
    endpoint="/api/tools/subfinder"
)
def subfinder_enum(domain: str, silent: bool = True, all_sources: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    if all_sources:
        cmd.append("-all")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="nmap_advanced_scan",
    category="network",
    description="Advanced Nmap scans with custom NSE scripts and optimized timing - for deep scripted analysis after initial discovery, not a first pass",
    endpoint="/api/tools/nmap-advanced"
)
def nmap_advanced_scan(
    target: str,
    scan_type: Annotated[str, Field(description="Raw Nmap scan flag(s), e.g. '-sS' (SYN stealth), '-sV' (version detection)")] = "-sS",
    ports: Optional[str] = None,
    timing: Annotated[str, Field(description="Nmap timing template T0 (slowest/most stealthy) to T5 (fastest/most aggressive); T4 is the common default")] = "T4",
    nse_scripts: Annotated[Optional[str], Field(description="Comma-separated NSE script names or categories to run, e.g. 'vuln,default' or 'http-title'")] = None,
    os_detection: bool = False,
    version_detection: bool = False,
    aggressive: bool = False,
    stealth: bool = False,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["nmap"] + scan_type.split() + [target]
    if ports:
        cmd.extend(["-p", ports])
    if stealth:
        cmd.extend(["-T2", "-f", "--mtu", "24"])
    else:
        cmd.append(f"-{timing}")
    if os_detection:
        cmd.append("-O")
    if version_detection:
        cmd.append("-sV")
    if aggressive:
        cmd.append("-A")
    if nse_scripts:
        cmd.append(f"--script={nse_scripts}")
    elif not aggressive:
        cmd.append("--script=default,discovery,safe")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
