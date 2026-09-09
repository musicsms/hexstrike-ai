from pathlib import Path
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command

@ToolRegistry.register(
    name="prowler_scan",
    category="cloud",
    description="AWS/multi-cloud security assessment using Prowler",
    endpoint="/api/tools/prowler"
)
def prowler_scan(provider: str = "aws", profile: Optional[str] = "default", region: Optional[str] = None, checks: Optional[str] = None, output_dir: str = "/tmp/prowler_output", output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["prowler", provider]
    if profile:
        cmd.extend(["--profile", profile])
    if region:
        cmd.extend(["--region", region])
    if checks:
        cmd.extend(["--checks", checks])
    cmd.extend(["--output-directory", output_dir])
    cmd.extend(["--output-format", output_format])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    result["output_directory"] = output_dir
    return result
