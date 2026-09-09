from pathlib import Path
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

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
def exiftool_scan(file_path: str, output_format: Optional[str] = None, tags: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
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
def steghide_run(cover_file: str, action: str = "extract", embed_file: Optional[str] = None, passphrase: Optional[str] = None, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
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
