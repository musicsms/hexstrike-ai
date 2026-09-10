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

@ToolRegistry.register(
    name="hashcat_scan",
    category="password",
    description="Password hash cracking using Hashcat - GPU-accelerated, fastest option for supported hash types",
    endpoint="/api/tools/hashcat"
)
def hashcat_scan(hash_file: str, hash_type: str, attack_mode: str = "0", wordlist: Optional[str] = "/usr/share/wordlists/rockyou.txt", mask: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["hashcat", "-m", hash_type, "-a", attack_mode, hash_file]
    if attack_mode == "0" and wordlist:
        cmd.append(wordlist)
    elif attack_mode == "3" and mask:
        cmd.append(mask)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="john_scan",
    category="password",
    description="Password hash cracking using John the Ripper - CPU-based, broader legacy format support than Hashcat",
    endpoint="/api/tools/john"
)
def john_scan(hash_file: str, wordlist: Optional[str] = "/usr/share/wordlists/rockyou.txt", format: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["john"]
    if format:
        cmd.append(f"--format={format}")
    if wordlist:
        cmd.append(f"--wordlist={wordlist}")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(hash_file)
    return run_tool_command(cmd)
