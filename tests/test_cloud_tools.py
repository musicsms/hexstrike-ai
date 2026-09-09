import pytest
from pathlib import Path
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    """Bypass real binary lookup and subprocess execution, capture the built command."""
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_prowler_scan_handler_invocation(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("prowler_scan")
    assert tool is not None
    assert tool.category == "cloud"
    assert tool.endpoint == "/api/tools/prowler"

    output_dir = str(tmp_path / "prowler_output")
    res = tool.handler(
        provider="aws", profile="myprofile", region="us-east-1", checks="check1,check2",
        output_dir=output_dir, output_format="json", additional_args="-M csv",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "prowler", "aws",
        "--profile", "myprofile",
        "--region", "us-east-1",
        "--checks", "check1,check2",
        "--output-directory", output_dir,
        "--output-format", "json",
        "-M", "csv",
    ]
    assert res["output_directory"] == output_dir
    assert Path(output_dir).is_dir()


def test_trivy_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("trivy_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/trivy"

    res = tool.handler(
        target="myimage:latest", scan_type="image", output_format="json",
        severity="HIGH,CRITICAL", output_file="/tmp/out.json", additional_args="--timeout 5m",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "trivy", "image", "myimage:latest",
        "--format", "json", "--severity", "HIGH,CRITICAL", "--output", "/tmp/out.json",
        "--timeout", "5m",
    ]
    assert res["output_file"] == "/tmp/out.json"

    res2 = tool.handler(target="myimage:latest")
    assert "output_file" not in res2


def test_scout_suite_scan_handler_invocation_aws(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("scout_suite_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/scout-suite"

    report_dir = str(tmp_path / "scout-report")
    res = tool.handler(
        provider="aws", profile="myprofile", report_dir=report_dir,
        services="s3,ec2", exceptions="exc.json", additional_args="--no-browser",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "scout", "aws",
        "--profile", "myprofile",
        "--services", "s3,ec2",
        "--exceptions", "exc.json",
        "--report-dir", report_dir,
        "--no-browser",
    ]
    assert res["report_directory"] == report_dir
    assert Path(report_dir).is_dir()


def test_scout_suite_scan_handler_invocation_non_aws_skips_profile(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("scout_suite_scan")

    report_dir = str(tmp_path / "scout-report-azure")
    res = tool.handler(provider="azure", profile="myprofile", report_dir=report_dir)
    assert res["success"] is True
    assert captured["cmd"] == ["scout", "azure", "--report-dir", report_dir]


def test_cloudmapper_run_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("cloudmapper_run")
    assert tool is not None
    assert tool.endpoint == "/api/tools/cloudmapper"

    res = tool.handler(action="collect", account="123456789", config="myconfig.json", additional_args="--verbose")
    assert res["success"] is True
    assert captured["cmd"] == ["cloudmapper", "collect", "--account", "123456789", "--config", "myconfig.json", "--verbose"]


def test_kube_hunter_scan_handler_invocation_target(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/kube-hunter"

    res = tool.handler(target="10.0.0.1", active=True, report="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--remote", "10.0.0.1", "--active", "--report", "json", "-v"]


def test_kube_hunter_scan_handler_invocation_default_pod(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")

    res = tool.handler(report="json")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--pod", "--report", "json"]
