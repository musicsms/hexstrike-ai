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

@ToolRegistry.register(
    name="httpx_probe",
    category="web",
    description="Fast HTTP probing and technology detection using httpx",
    endpoint="/api/tools/httpx"
)
def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False, status_code: bool = False, content_length: bool = False, title: bool = False, web_server: bool = False, threads: int = 50, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["httpx", "-l", target, "-t", str(threads)]
    if probe:
        cmd.append("-probe")
    if tech_detect:
        cmd.append("-tech-detect")
    if status_code:
        cmd.append("-sc")
    if content_length:
        cmd.append("-cl")
    if title:
        cmd.append("-title")
    if web_server:
        cmd.append("-server")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="jaeles_scan",
    category="web",
    description="Advanced vulnerability scanning with custom signatures using Jaeles",
    endpoint="/api/tools/jaeles"
)
def jaeles_scan(url: str, signatures: Optional[str] = None, config: Optional[str] = None, threads: int = 20, timeout: int = 20, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["jaeles", "scan", "-u", url, "-c", str(threads), "--timeout", str(timeout)]
    if signatures:
        cmd.extend(["-s", signatures])
    if config:
        cmd.extend(["--config", config])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="katana_crawl",
    category="web",
    description="Next-generation web crawling and spidering using Katana",
    endpoint="/api/tools/katana"
)
def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True, form_extraction: bool = True, output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["katana", "-u", url, "-d", str(depth)]
    if js_crawl:
        cmd.append("-jc")
    if form_extraction:
        cmd.append("-fx")
    if output_format == "json":
        cmd.append("-jsonl")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="nikto_scan",
    category="web",
    description="Web server vulnerability scanning using Nikto",
    endpoint="/api/tools/nikto"
)
def nikto_scan(target: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nikto", "-h", target]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="nuclei_scan",
    category="web",
    description="Vulnerability scanning using Nuclei templates",
    endpoint="/api/tools/nuclei"
)
def nuclei_scan(target: str, severity: Optional[str] = None, tags: Optional[str] = None, template: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nuclei", "-u", target]
    if severity:
        cmd.extend(["-severity", severity])
    if tags:
        cmd.extend(["-tags", tags])
    if template:
        cmd.extend(["-t", template])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="paramspider_mine",
    category="web",
    description="Parameter mining from web archives using ParamSpider",
    endpoint="/api/tools/paramspider"
)
def paramspider_mine(domain: str, level: int = 2, exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", output: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["paramspider", "-d", domain, "-l", str(level)]
    if exclude:
        cmd.extend(["--exclude", exclude])
    if output:
        cmd.extend(["-o", output])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="wafw00f_scan",
    category="web",
    description="WAF fingerprinting using wafw00f",
    endpoint="/api/tools/wafw00f"
)
def wafw00f_scan(target: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wafw00f", target]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="waybackurls_discover",
    category="web",
    description="Historical URL discovery using Waybackurls",
    endpoint="/api/tools/waybackurls"
)
def waybackurls_discover(domain: str, get_versions: bool = False, no_subs: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["waybackurls", domain]
    if get_versions:
        cmd.append("--get-versions")
    if no_subs:
        cmd.append("--no-subs")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="wfuzz_scan",
    category="web",
    description="Web application fuzzing using Wfuzz",
    endpoint="/api/tools/wfuzz"
)
def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wfuzz", "-w", wordlist, url]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
