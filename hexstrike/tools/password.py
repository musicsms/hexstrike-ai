from typing import Dict, Any, Optional, Annotated
from pydantic import Field
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
def hashcat_scan(
    hash_file: str,
    hash_type: Annotated[str, Field(description="Hashcat -m hash-type code, e.g. '0' (MD5), '1000' (NTLM), '1800' (sha512crypt)")],
    attack_mode: Annotated[str, Field(description="Hashcat -a attack mode: '0' wordlist, '1' combinator, '3' brute-force mask, '6'/'7' hybrid")] = "0",
    wordlist: Annotated[Optional[str], Field(description="Wordlist path, used only when attack_mode is '0' (wordlist attack)")] = "/usr/share/wordlists/rockyou.txt",
    mask: Annotated[Optional[str], Field(description="Hashcat mask string, used only when attack_mode is '3', e.g. '?a?a?a?a?a?a' for 6 arbitrary characters")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
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
def john_scan(
    hash_file: str,
    wordlist: Optional[str] = "/usr/share/wordlists/rockyou.txt",
    format: Annotated[Optional[str], Field(description="John --format hash type, e.g. 'raw-md5', 'nt', 'sha512crypt', 'bcrypt' (omit to let John auto-detect)")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["john"]
    if format:
        cmd.append(f"--format={format}")
    if wordlist:
        cmd.append(f"--wordlist={wordlist}")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(hash_file)
    return run_tool_command(cmd)
