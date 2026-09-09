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

@ToolRegistry.register(
    name="trivy_scan",
    category="cloud",
    description="Container/filesystem vulnerability scanning using Trivy",
    endpoint="/api/tools/trivy"
)
def trivy_scan(target: str, scan_type: str = "image", output_format: str = "json", severity: Optional[str] = None, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["trivy", scan_type, target]
    if output_format:
        cmd.extend(["--format", output_format])
    if severity:
        cmd.extend(["--severity", severity])
    if output_file:
        cmd.extend(["--output", output_file])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    if output_file:
        result["output_file"] = output_file
    return result

@ToolRegistry.register(
    name="scout_suite_scan",
    category="cloud",
    description="Multi-cloud security assessment using Scout Suite",
    endpoint="/api/tools/scout-suite"
)
def scout_suite_scan(provider: str = "aws", profile: Optional[str] = "default", report_dir: str = "/tmp/scout-suite", services: Optional[str] = None, exceptions: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["scout", provider]
    if profile and provider == "aws":
        cmd.extend(["--profile", profile])
    if services:
        cmd.extend(["--services", services])
    if exceptions:
        cmd.extend(["--exceptions", exceptions])
    cmd.extend(["--report-dir", report_dir])
    if additional_args:
        cmd.extend(additional_args.split())
    result = run_tool_command(cmd)
    result["report_directory"] = report_dir
    return result

@ToolRegistry.register(
    name="cloudmapper_run",
    category="cloud",
    description="AWS network visualization and security analysis using CloudMapper",
    endpoint="/api/tools/cloudmapper"
)
def cloudmapper_run(action: str = "collect", account: Optional[str] = None, config: Optional[str] = "config.json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["cloudmapper", action]
    if account:
        cmd.extend(["--account", account])
    if config:
        cmd.extend(["--config", config])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="kube_hunter_scan",
    category="cloud",
    description="Kubernetes penetration testing using kube-hunter",
    endpoint="/api/tools/kube-hunter"
)
def kube_hunter_scan(target: Optional[str] = None, remote: Optional[str] = None, cidr: Optional[str] = None, interface: Optional[str] = None, active: bool = False, report: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["kube-hunter"]
    if target:
        cmd.extend(["--remote", target])
    elif remote:
        cmd.extend(["--remote", remote])
    elif cidr:
        cmd.extend(["--cidr", cidr])
    elif interface:
        cmd.extend(["--interface", interface])
    else:
        cmd.append("--pod")
    if active:
        cmd.append("--active")
    if report:
        cmd.extend(["--report", report])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="kube_bench_scan",
    category="cloud",
    description="CIS Kubernetes benchmark checks using kube-bench",
    endpoint="/api/tools/kube-bench"
)
def kube_bench_scan(targets: Optional[str] = None, version: Optional[str] = None, config_dir: Optional[str] = None, output_format: str = "json", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["kube-bench"]
    if targets:
        cmd.extend(["--targets", targets])
    if version:
        cmd.extend(["--version", version])
    if config_dir:
        cmd.extend(["--config-dir", config_dir])
    if output_format:
        cmd.extend(["--outputfile", f"/tmp/kube-bench-results.{output_format}", "--json"])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)
