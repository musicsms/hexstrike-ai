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


def test_masscan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("masscan_scan")
    assert tool is not None
    assert tool.category == "network"
    assert tool.endpoint == "/api/tools/masscan"

    res = tool.handler(
        target="192.168.1.0/24",
        ports="80,443",
        rate=500,
        interface="eth0",
        router_mac="00:11:22:33:44:55",
        source_ip="10.0.0.5",
        banners=True,
        additional_args="--wait 5",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "masscan", "192.168.1.0/24", "-p80,443", "--rate=500",
        "-e", "eth0",
        "--router-mac", "00:11:22:33:44:55",
        "--source-ip", "10.0.0.5",
        "--banners",
        "--wait", "5",
    ]
