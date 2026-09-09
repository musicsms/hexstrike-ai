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


def test_dalfox_scan_handler_invocation_url_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dalfox_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dalfox"

    res = tool.handler(
        url="http://x.com", blind=True, mining_dom=True, mining_dict=True,
        custom_payload="<script>", additional_args="--silence",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "dalfox", "url", "http://x.com", "--blind", "--mining-dom", "--mining-dict",
        "--custom-payload", "<script>", "--silence",
    ]


def test_dalfox_scan_handler_invocation_pipe_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dalfox_scan")

    res = tool.handler(pipe_mode=True, mining_dom=False, mining_dict=False)
    assert res["success"] is True
    assert captured["cmd"] == ["dalfox", "pipe"]


def test_dirb_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dirb_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dirb"

    res = tool.handler(url="http://x.com", additional_args="-S")
    assert res["success"] is True
    assert captured["cmd"] == ["dirb", "http://x.com", "/usr/share/wordlists/dirb/common.txt", "-S"]
