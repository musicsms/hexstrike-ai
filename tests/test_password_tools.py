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


def test_hashcat_scan_handler_invocation_wordlist_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hashcat_scan")
    assert tool is not None
    assert tool.category == "password"
    assert tool.endpoint == "/api/tools/hashcat"

    res = tool.handler(
        hash_file="/tmp/h.txt", hash_type="0", attack_mode="0",
        wordlist="/tmp/rockyou.txt", additional_args="--force",
    )
    assert res["success"] is True
    assert captured["cmd"] == ["hashcat", "-m", "0", "-a", "0", "/tmp/h.txt", "/tmp/rockyou.txt", "--force"]


def test_hashcat_scan_handler_invocation_mask_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hashcat_scan")

    res = tool.handler(hash_file="/tmp/h.txt", hash_type="1000", attack_mode="3", mask="?a?a?a?a")
    assert res["success"] is True
    assert captured["cmd"] == ["hashcat", "-m", "1000", "-a", "3", "/tmp/h.txt", "?a?a?a?a"]


def test_john_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("john_scan")
    assert tool is not None
    assert tool.category == "password"
    assert tool.endpoint == "/api/tools/john"

    res = tool.handler(hash_file="/tmp/h.txt", wordlist="/tmp/rockyou.txt", format="raw-md5", additional_args="--fork=4")
    assert res["success"] is True
    assert captured["cmd"] == ["john", "--format=raw-md5", "--wordlist=/tmp/rockyou.txt", "--fork=4", "/tmp/h.txt"]


def test_password_category_has_3_tools():
    password_tools = ToolRegistry.get_by_category("password")
    assert len(password_tools) == 3
    names = {t.name for t in password_tools}
    assert names == {"hydra_attack", "hashcat_scan", "john_scan"}
