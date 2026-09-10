from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="amass_enum",
    category="osint",
    description="In-depth DNS enumeration and network mapping using OWASP Amass - active+passive, slower and more thorough than subfinder_enum",
    endpoint="/api/tools/amass"
)
def amass_enum(domain: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["amass", "enum", "-d", domain]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="hakrawler_crawl",
    category="osint",
    description="Web endpoint discovery and crawling using Hakrawler",
    endpoint="/api/tools/hakrawler"
)
def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["hakrawler", "-url", url, "-d", str(depth)]
    if forms:
        cmd.append("-s")
    if robots or sitemap or wayback:
        cmd.append("-subs")
    cmd.append("-u")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
