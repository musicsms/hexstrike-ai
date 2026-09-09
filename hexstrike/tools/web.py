from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="ffuf_fuzz",
    category="web",
    description="Fast web fuzzer using ffuf",
    endpoint="/api/tools/ffuf"
)
def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["ffuf", "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="gobuster_dir",
    category="web",
    description="Directory and DNS busting using Gobuster",
    endpoint="/api/tools/gobuster"
)
def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="sqlmap_scan",
    category="web",
    description="Automated SQL injection scanner using SQLMap",
    endpoint="/api/tools/sqlmap"
)
def sqlmap_scan(url: str, batch: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["sqlmap", "-u", url]
    if batch:
        cmd.append("--batch")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="arjun_scan",
    category="web",
    description="HTTP parameter discovery using Arjun",
    endpoint="/api/tools/arjun"
)
def arjun_scan(url: str, method: str = "GET", wordlist: Optional[str] = None, delay: int = 0, threads: int = 25, stable: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["arjun", "-u", url, "-m", method, "-t", str(threads)]
    if wordlist:
        cmd.extend(["-w", wordlist])
    if delay > 0:
        cmd.extend(["-d", str(delay)])
    if stable:
        cmd.append("--stable")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dalfox_scan",
    category="web",
    description="Advanced XSS vulnerability scanning using Dalfox",
    endpoint="/api/tools/dalfox"
)
def dalfox_scan(url: Optional[str] = None, pipe_mode: bool = False, blind: bool = False, mining_dom: bool = True, mining_dict: bool = True, custom_payload: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    if pipe_mode:
        cmd = ["dalfox", "pipe"]
    else:
        cmd = ["dalfox", "url", url]
    if blind:
        cmd.append("--blind")
    if mining_dom:
        cmd.append("--mining-dom")
    if mining_dict:
        cmd.append("--mining-dict")
    if custom_payload:
        cmd.extend(["--custom-payload", custom_payload])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dirb_scan",
    category="web",
    description="Directory and file brute-forcing using dirb",
    endpoint="/api/tools/dirb"
)
def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dirb", url, wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dirsearch_scan",
    category="web",
    description="Advanced directory and file discovery using Dirsearch",
    endpoint="/api/tools/dirsearch"
)
def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json", wordlist: str = "/usr/share/wordlists/dirsearch/common.txt", threads: int = 30, recursive: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dirsearch", "-u", url, "-e", extensions, "-w", wordlist, "-t", str(threads)]
    if recursive:
        cmd.append("-r")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dotdotpwn_scan",
    category="web",
    description="Directory traversal fuzzing using DotDotPwn",
    endpoint="/api/tools/dotdotpwn"
)
def dotdotpwn_scan(target: str, module: str = "http", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dotdotpwn", "-m", module, "-h", target]
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append("-b")
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="feroxbuster_scan",
    category="web",
    description="Recursive content discovery using Feroxbuster",
    endpoint="/api/tools/feroxbuster"
)
def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "-t", str(threads)]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="gau_discover",
    category="web",
    description="URL discovery from multiple archive sources using Gau",
    endpoint="/api/tools/gau"
)
def gau_discover(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan", include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gau", domain]
    if providers != "wayback,commoncrawl,otx,urlscan":
        cmd.extend(["--providers", providers])
    if include_subs:
        cmd.append("--subs")
    if blacklist:
        cmd.extend(["--blacklist", blacklist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
