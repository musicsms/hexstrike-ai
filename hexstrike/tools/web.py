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
