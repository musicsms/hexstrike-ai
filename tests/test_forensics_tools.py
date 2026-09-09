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


def test_binwalk_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("binwalk_scan")
    assert tool is not None
    assert tool.category == "forensics"
    assert tool.endpoint == "/api/tools/binwalk"

    res = tool.handler(file_path="/tmp/fw.bin", extract=True, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["binwalk", "-e", "-v", "/tmp/fw.bin"]
