from pathlib import Path
from typing import Dict, Any, Optional, Annotated
from pydantic import Field
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command, resolve_binary

@ToolRegistry.register(
    name="binwalk_scan",
    category="forensics",
    description="Firmware and file analysis using Binwalk",
    endpoint="/api/tools/binwalk"
)
def binwalk_scan(file_path: str, extract: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="exiftool_scan",
    category="forensics",
    description="Metadata extraction using ExifTool",
    endpoint="/api/tools/exiftool"
)
def exiftool_scan(
    file_path: str,
    output_format: Annotated[Optional[str], Field(description="ExifTool output flag without the leading dash, e.g. 'json', 'xml', 'csv'")] = None,
    tags: Annotated[Optional[str], Field(description="Specific tag to extract, without the leading dash, e.g. 'GPS:all' or 'DateTimeOriginal'")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["exiftool"]
    if output_format:
        cmd.append(f"-{output_format}")
    if tags:
        cmd.append(f"-{tags}")
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(file_path)
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="foremost_scan",
    category="forensics",
    description="File carving using Foremost",
    endpoint="/api/tools/foremost"
)
def foremost_scan(input_file: str, output_dir: str = "/tmp/foremost_output", file_types: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["foremost", "-o", output_dir]
    if file_types:
        cmd.extend(["-t", file_types])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(input_file)
    result = run_tool_command(cmd)
    result["output_directory"] = output_dir
    return result

@ToolRegistry.register(
    name="steghide_run",
    category="forensics",
    description="Steganography analysis using Steghide",
    endpoint="/api/tools/steghide"
)
def steghide_run(
    cover_file: str,
    action: Annotated[str, Field(description="'extract' to pull hidden data out of cover_file, 'embed' to hide embed_file inside it, 'info' to inspect cover_file without extracting")] = "extract",
    embed_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    output_file: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    if action == "extract":
        cmd = ["steghide", "extract", "-sf", cover_file]
        if output_file:
            cmd.extend(["-xf", output_file])
    elif action == "embed":
        cmd = ["steghide", "embed", "-cf", cover_file, "-ef", embed_file]
    elif action == "info":
        cmd = ["steghide", "info", cover_file]
    if passphrase:
        cmd.extend(["-p", passphrase])
    else:
        cmd.extend(["-p", ""])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="volatility_scan",
    category="forensics",
    description="Memory forensics using Volatility - legacy 2.x branch, needed only for older/unsupported profiles",
    endpoint="/api/tools/volatility"
)
def volatility_scan(
    memory_file: str,
    plugin: Annotated[str, Field(description="Volatility 2.x plugin name, e.g. 'pslist', 'netscan', 'malfind', 'hivelist'")],
    profile: Annotated[Optional[str], Field(description="OS profile identifying the memory image, e.g. 'Win7SP1x64', 'LinuxUbuntu1804x64' (required by most plugins on Volatility 2.x)")] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["volatility", "-f", memory_file]
    if profile:
        cmd.append(f"--profile={profile}")
    cmd.append(plugin)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="volatility3_scan",
    category="forensics",
    description="Advanced memory forensics using Volatility 3 - actively maintained, prefer this unless a legacy profile requires volatility_scan",
    endpoint="/api/tools/volatility3"
)
def volatility3_scan(
    memory_file: str,
    plugin: Annotated[str, Field(description="Volatility 3 plugin name, e.g. 'windows.pslist', 'windows.netscan', 'linux.bash' (Volatility 3 auto-detects the OS profile, unlike volatility_scan)")],
    output_file: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    # "vol" is the console-script name from a pip install; "vol.py" is the
    # launcher used when running from a volatility3 source checkout.
    cmd = [resolve_binary("volatility3", ["vol", "vol.py"]), "-f", memory_file, plugin]
    if output_file:
        cmd.extend(["-o", output_file])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
