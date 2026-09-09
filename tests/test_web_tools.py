import pytest
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


def test_arjun_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("arjun_scan")
    assert tool is not None
    assert tool.category == "web"
    assert tool.endpoint == "/api/tools/arjun"

    res = tool.handler(
        url="http://x.com", method="POST", wordlist="/tmp/wl.txt",
        delay=2, threads=10, stable=True, additional_args="--include X",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "arjun", "-u", "http://x.com", "-m", "POST", "-t", "10",
        "-w", "/tmp/wl.txt", "-d", "2", "--stable", "--include", "X",
    ]
