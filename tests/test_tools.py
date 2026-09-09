import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools

def test_tools_registered():
    nmap = ToolRegistry.get("nmap_scan")
    assert nmap is not None
    assert nmap.category == "network"
    assert nmap.endpoint == "/api/tools/nmap"

    ffuf = ToolRegistry.get("ffuf_fuzz")
    assert ffuf is not None
    assert ffuf.category == "web"
    assert ffuf.endpoint == "/api/tools/ffuf"

def test_nmap_handler_invocation(monkeypatch):
    from hexstrike.core.process import default_process_manager
    nmap = ToolRegistry.get("nmap_scan")

    def mock_execute(cmd, **kwargs):
        return {"success": True, "command": " ".join(cmd), "output": "Nmap scan report", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", mock_execute)
    res = nmap.handler(target="127.0.0.1", scan_type="-sV")
    assert res["success"] is True
    assert "nmap" in res["command"]
    assert "127.0.0.1" in res["command"]
