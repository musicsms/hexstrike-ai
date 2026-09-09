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
