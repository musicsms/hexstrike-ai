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


def test_exiftool_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("exiftool_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/exiftool"

    res = tool.handler(file_path="/tmp/img.jpg", output_format="json", tags="GPS", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["exiftool", "-json", "-GPS", "-v", "/tmp/img.jpg"]


def test_foremost_scan_handler_invocation(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("foremost_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/foremost"

    output_dir = str(tmp_path / "foremost_output")
    res = tool.handler(input_file="/tmp/disk.img", output_dir=output_dir, file_types="jpg,png", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["foremost", "-o", output_dir, "-t", "jpg,png", "-v", "/tmp/disk.img"]
    assert res["output_directory"] == output_dir
    assert Path(output_dir).is_dir()


def test_steghide_run_handler_invocation_extract(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("steghide_run")
    assert tool is not None
    assert tool.endpoint == "/api/tools/steghide"

    res = tool.handler(cover_file="/tmp/img.jpg", action="extract", output_file="/tmp/out.txt", passphrase="secret", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["steghide", "extract", "-sf", "/tmp/img.jpg", "-xf", "/tmp/out.txt", "-p", "secret", "-v"]


def test_steghide_run_handler_invocation_embed_no_passphrase(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("steghide_run")

    res = tool.handler(cover_file="/tmp/img.jpg", action="embed", embed_file="/tmp/secret.txt")
    assert res["success"] is True
    assert captured["cmd"] == ["steghide", "embed", "-cf", "/tmp/img.jpg", "-ef", "/tmp/secret.txt", "-p", ""]


def test_steghide_run_handler_invocation_info(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("steghide_run")

    res = tool.handler(cover_file="/tmp/img.jpg", action="info", passphrase="pw")
    assert res["success"] is True
    assert captured["cmd"] == ["steghide", "info", "/tmp/img.jpg", "-p", "pw"]


def test_volatility_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("volatility_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/volatility"

    res = tool.handler(memory_file="/tmp/mem.dmp", plugin="pslist", profile="Win10x64", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["volatility", "-f", "/tmp/mem.dmp", "--profile=Win10x64", "pslist", "-v"]


def test_volatility3_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("volatility3_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/volatility3"

    res = tool.handler(memory_file="/tmp/mem.dmp", plugin="windows.pslist", output_file="/tmp/out.txt", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["vol.py", "-f", "/tmp/mem.dmp", "windows.pslist", "-o", "/tmp/out.txt", "-v"]
