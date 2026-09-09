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


def test_arp_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("arp_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/arp-scan"

    res = tool.handler(
        interface="eth0",
        local_network=True,
        timeout=200,
        retry=5,
        additional_args="-v",
    )
    assert res["success"] is True
    assert captured["cmd"] == ["arp-scan", "-t", "200", "-r", "5", "-I", "eth0", "-l", "-v"]

    res2 = tool.handler(target="192.168.1.1")
    assert captured["cmd"] == ["arp-scan", "-t", "500", "-r", "3", "192.168.1.1"]


def test_autorecon_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("autorecon_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/autorecon"

    res = tool.handler(target="10.0.0.5")
    assert res["success"] is True
    assert captured["cmd"] == [
        "autorecon", "10.0.0.5", "-o", "/tmp/autorecon",
        "--heartbeat", "60", "--timeout", "300",
        "--port-scans", "top-100-ports",
    ]

    res2 = tool.handler(target="10.0.0.5", port_scans="default", service_scans="all", additional_args="-vv")
    assert captured["cmd"] == [
        "autorecon", "10.0.0.5", "-o", "/tmp/autorecon",
        "--heartbeat", "60", "--timeout", "300",
        "--service-scans", "all", "-vv",
    ]


def test_dnsenum_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dnsenum_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dnsenum"

    res = tool.handler(domain="example.com", dns_server="8.8.8.8", wordlist="/tmp/wl.txt", additional_args="--threads 5")
    assert res["success"] is True
    assert captured["cmd"] == ["dnsenum", "example.com", "--dnsserver", "8.8.8.8", "--file", "/tmp/wl.txt", "--threads", "5"]


def test_enum4linux_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("enum4linux_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/enum4linux"

    res = tool.handler(target="10.0.0.1")
    assert res["success"] is True
    assert captured["cmd"] == ["enum4linux", "-a", "10.0.0.1"]

    res2 = tool.handler(target="10.0.0.1", additional_args="-u guest")
    assert captured["cmd"] == ["enum4linux", "-u", "guest", "10.0.0.1"]


def test_enum4linux_ng_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("enum4linux_ng_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/enum4linux-ng"

    res = tool.handler(
        target="10.0.0.1", username="admin", password="pass123", domain="CORP",
        shares=True, users=True, groups=False, policy=True, additional_args="--verbose",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "enum4linux-ng", "10.0.0.1", "-u", "admin", "-p", "pass123", "-d", "CORP",
        "-A", "S,U,P", "--verbose",
    ]
