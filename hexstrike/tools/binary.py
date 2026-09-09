from pathlib import Path
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="radare2_analyze",
    category="binary",
    description="Reverse engineering framework using radare2",
    endpoint="/api/tools/radare2"
)
def radare2_analyze(file_path: str, commands: str = "aaa; afl") -> Dict[str, Any]:
    cmd = ["r2", "-q", "-c", commands, file_path]
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="gdb_analyze",
    category="binary",
    description="Binary analysis and debugging using GDB",
    endpoint="/api/tools/gdb"
)
def gdb_analyze(binary: str, commands: Optional[str] = None, script_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
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
    description="Advanced binary analysis and reverse engineering using Ghidra",
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
    description="ROP gadget search using ROPgadget",
    endpoint="/api/tools/ropgadget"
)
def ropgadget_scan(binary: str, gadget_type: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
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
    description="Binary analysis using objdump",
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
    description="Advanced ROP/JOP gadget search using ropper",
    endpoint="/api/tools/ropper"
)
def ropper_scan(binary: str, gadget_type: str = "rop", quality: int = 1, arch: Optional[str] = None, search_string: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["ropper", "--file", binary]
    if gadget_type == "rop":
        cmd.append("--rop")
    elif gadget_type == "jop":
        cmd.append("--jop")
    elif gadget_type == "sys":
        cmd.append("--sys")
    elif gadget_type == "all":
        cmd.append("--all")
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
def pwninit_setup(binary: str, libc: Optional[str] = None, ld: Optional[str] = None, template_type: Optional[str] = "python", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["pwninit", "--bin", binary]
    if libc:
        cmd.extend(["--libc", libc])
    if ld:
        cmd.extend(["--ld", ld])
    if template_type:
        cmd.extend(["--template", template_type])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="one_gadget_find",
    category="binary",
    description="One-shot RCE gadget search in libc using one_gadget",
    endpoint="/api/tools/one-gadget"
)
def one_gadget_find(libc_path: str, level: int = 1, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["one_gadget", libc_path, "--level", str(level)]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
