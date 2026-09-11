from pathlib import Path
from typing import Dict, Any, Optional, Annotated
from pydantic import Field
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="radare2_analyze",
    category="binary",
    description="Reverse engineering framework using radare2 - lightweight, scriptable static analysis and disassembly",
    endpoint="/api/tools/radare2"
)
def radare2_analyze(
    file_path: str,
    commands: Annotated[str, Field(description="Semicolon-separated radare2 command string, e.g. 'aaa; afl' (analyze all, list functions)")] = "aaa; afl",
) -> Dict[str, Any]:
    cmd = ["r2", "-q", "-c", commands, file_path]
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="gdb_analyze",
    category="binary",
    description="Binary analysis and debugging using GDB - live/dynamic debugging (breakpoints, memory inspection), not static analysis",
    endpoint="/api/tools/gdb"
)
def gdb_analyze(
    binary: str,
    commands: Annotated[Optional[str], Field(description="Newline-separated GDB commands to run in batch mode, e.g. 'break main\\nrun\\ninfo registers'")] = None,
    script_file: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["gdb", binary]
    if script_file:
        cmd.extend(["-x", script_file])
    if commands:
        Path("/tmp/gdb_commands.txt").write_text(commands)
        cmd.extend(["-x", "/tmp/gdb_commands.txt"])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append("-batch")
    result = run_tool_command(cmd)
    if commands and Path("/tmp/gdb_commands.txt").exists():
        try:
            Path("/tmp/gdb_commands.txt").unlink()
        except OSError:
            pass
    return result

@ToolRegistry.register(
    name="ghidra_analyze",
    category="binary",
    description="Advanced binary analysis and reverse engineering using Ghidra - full decompiler, best for deep static analysis of unfamiliar binaries",
    endpoint="/api/tools/ghidra"
)
def ghidra_analyze(binary: str, project_name: str = "hexstrike_analysis", script_file: Optional[str] = None, analysis_timeout: int = 300, output_format: str = "xml", additional_args: Optional[str] = None) -> Dict[str, Any]:
    project_dir = f"/tmp/ghidra_projects/{project_name}"
    Path(project_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["analyzeHeadless", project_dir, project_name, "-import", binary, "-deleteProject"]
    if script_file:
        cmd.extend(["-postScript", script_file])
    if output_format == "xml":
        cmd.extend(["-postScript", "ExportXml.java", f"{project_dir}/analysis.xml"])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=analysis_timeout)

@ToolRegistry.register(
    name="ropgadget_scan",
    category="binary",
    description="ROP gadget search using ROPgadget - simple, fast gadget listing",
    endpoint="/api/tools/ropgadget"
)
def ropgadget_scan(
    binary: str,
    gadget_type: Annotated[Optional[str], Field(description="Restrict to one gadget class, e.g. 'pop|ret', 'jmp', 'call' (ROPgadget's --only filter)")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["ROPgadget", "--binary", binary]
    if gadget_type:
        cmd.extend(["--only", gadget_type])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="checksec_scan",
    category="binary",
    description="Binary security feature check using Checksec",
    endpoint="/api/tools/checksec"
)
def checksec_scan(binary: str) -> Dict[str, Any]:
    cmd = ["checksec", f"--file={binary}"]
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="xxd_dump",
    category="binary",
    description="Hex dump generation using xxd",
    endpoint="/api/tools/xxd"
)
def xxd_dump(file_path: str, offset: str = "0", length: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["xxd", "-s", offset]
    if length:
        cmd.extend(["-l", length])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="strings_scan",
    category="binary",
    description="String extraction from binary files using strings",
    endpoint="/api/tools/strings"
)
def strings_scan(file_path: str, min_len: int = 4, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["strings", "-n", str(min_len)]
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="objdump_scan",
    category="binary",
    description="Binary analysis using objdump - quick disassembly/header dump, lighter weight than radare2/Ghidra",
    endpoint="/api/tools/objdump"
)
def objdump_scan(binary: str, disassemble: bool = True, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["objdump"]
    if disassemble:
        cmd.append("-d")
    else:
        cmd.append("-x")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(binary)
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="ropper_scan",
    category="binary",
    description="Advanced ROP/JOP gadget search using ropper - also finds JOP/SYS gadgets with quality filtering, more capable than ropgadget_scan",
    endpoint="/api/tools/ropper"
)
def ropper_scan(
    binary: str,
    gadget_type: Annotated[str, Field(description="Gadget class to search: 'rop', 'jop', 'sys', or 'all'")] = "rop",
    quality: Annotated[int, Field(description="Gadget quality filter, 1-5; only values >1 are passed to ropper's --quality (stricter = fewer, cleaner gadgets)")] = 1,
    arch: Optional[str] = None,
    search_string: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["ropper", "--file", binary, "--type", gadget_type]
    if quality > 1:
        cmd.extend(["--quality", str(quality)])
    if arch:
        cmd.extend(["--arch", arch])
    if search_string:
        cmd.extend(["--search", search_string])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="pwninit_setup",
    category="binary",
    description="CTF binary exploitation setup using pwninit",
    endpoint="/api/tools/pwninit"
)
def pwninit_setup(
    binary: str,
    libc: Optional[str] = None,
    ld: Optional[str] = None,
    template_path: Annotated[Optional[str], Field(description="Path to a custom Jinja2 exploit template file for pwninit to render instead of its built-in template")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["pwninit", "--bin", binary]
    if libc:
        cmd.extend(["--libc", libc])
    if ld:
        cmd.extend(["--ld", ld])
    if template_path:
        cmd.extend(["--template-path", template_path])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="one_gadget_find",
    category="binary",
    description="One-shot RCE gadget search in libc using one_gadget",
    endpoint="/api/tools/one-gadget"
)
def one_gadget_find(
    libc_path: str,
    level: Annotated[int, Field(description="Constraint strictness 0-2: 0 finds only unconditionally-usable gadgets, 2 includes gadgets needing extra memory/register setup")] = 1,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["one_gadget", libc_path, "--level", str(level)]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="pwntools_exploit",
    category="binary",
    description="Exploit development and automation using Pwntools",
    endpoint="/api/tools/pwntools"
)
def pwntools_exploit(
    script_content: Optional[str] = None,
    target_binary: str = "",
    target_host: str = "",
    target_port: int = 0,
    exploit_type: Annotated[str, Field(description="Not currently read by the generated template - the template picks local vs remote automatically based on whether target_binary or target_host/target_port is set")] = "local",
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    script_file = "/tmp/pwntools_exploit.py"
    if script_content:
        Path(script_file).write_text(script_content)
    else:
        template = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
        Path(script_file).write_text(template)
    cmd = ["python3", script_file]
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    try:
        Path(script_file).unlink()
    except OSError:
        pass
    return result

@ToolRegistry.register(
    name="angr_analyze",
    category="binary",
    description="Symbolic execution and binary analysis using angr",
    endpoint="/api/tools/angr"
)
def angr_analyze(
    binary: str,
    script_content: Optional[str] = None,
    find_address: Optional[str] = None,
    avoid_addresses: Optional[str] = None,
    analysis_type: Annotated[str, Field(description="'symbolic' to run symbolic execution toward find_address/avoid_addresses, or 'cfg' to build and summarize a control-flow graph")] = "symbolic",
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    script_file = "/tmp/angr_analysis.py"
    if script_content:
        Path(script_file).write_text(script_content)
    else:
        template = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
        if analysis_type == "symbolic":
            template += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
        elif analysis_type == "cfg":
            template += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""
        Path(script_file).write_text(template)
    cmd = ["python3", script_file]
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd, timeout=600)
    try:
        Path(script_file).unlink()
    except OSError:
        pass
    return result

@ToolRegistry.register(
    name="gdb_peda_analyze",
    category="binary",
    description="Enhanced debugging and exploitation using GDB with PEDA - adds exploit-dev helpers (pattern search, heap inspection) on top of gdb_analyze",
    endpoint="/api/tools/gdb-peda"
)
def gdb_peda_analyze(
    binary: Optional[str] = None,
    commands: Annotated[Optional[str], Field(description="Newline-separated GDB/PEDA commands to run after PEDA loads, e.g. 'pattern create 200\\nrun'")] = None,
    attach_pid: int = 0,
    core_file: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["gdb", "-q"]
    if binary:
        cmd.append(binary)
    if core_file:
        cmd.append(core_file)
    if attach_pid:
        cmd.extend(["-p", str(attach_pid)])
    if commands:
        peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
        Path("/tmp/gdb_peda_commands.txt").write_text(peda_commands)
        cmd.extend(["-x", "/tmp/gdb_peda_commands.txt"])
    else:
        cmd.extend(["-ex", "source ~/peda/peda.py", "-ex", "quit"])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    if commands and Path("/tmp/gdb_peda_commands.txt").exists():
        try:
            Path("/tmp/gdb_peda_commands.txt").unlink()
        except OSError:
            pass
    return result

def _resolve_libc_database_dir() -> Optional[str]:
    if Path("/opt/libc-database").is_dir():
        return "/opt/libc-database"
    home_dir = Path.home() / "libc-database"
    if home_dir.is_dir():
        return str(home_dir)
    return None

@ToolRegistry.register(
    name="libc_database_lookup",
    category="binary",
    description="libc identification and offset lookup using libc-database",
    endpoint="/api/tools/libc-database"
)
def libc_database_lookup(
    action: Annotated[str, Field(description="'find' to search by leaked symbol addresses, 'dump' to dump offsets for a known libc_id, 'download' to fetch that libc binary")] = "find",
    symbols: Annotated[Optional[str], Field(description="Space-separated 'name address [name address ...]' pairs, e.g. 'puts 0x821 printf 0x67' (libc-database's ./find takes these as separate positional args, not a single combined string)")] = None,
    libc_id: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    if action == "find":
        cmd = ["./find"] + (symbols.split() if symbols else [])
    elif action == "dump":
        cmd = ["./dump", libc_id]
    elif action == "download":
        cmd = ["./download", libc_id]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, cwd=_resolve_libc_database_dir())
