import pytest
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_hakrawler_crawl_handler_invocation_defaults(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hakrawler_crawl")
    assert tool is not None
    assert tool.category == "osint"
    assert tool.endpoint == "/api/tools/hakrawler"

    res = tool.handler(url="https://example.com")
    assert res["success"] is True
    assert captured["cmd"] == ["hakrawler", "-url", "https://example.com", "-d", "2", "-s", "-subs", "-u"]


def test_hakrawler_crawl_handler_invocation_no_flags(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hakrawler_crawl")

    res = tool.handler(url="https://example.com", depth=5, forms=False, robots=False, sitemap=False, wayback=False, additional_args="-t 20")
    assert res["success"] is True
    assert captured["cmd"] == ["hakrawler", "-url", "https://example.com", "-d", "5", "-u", "-t", "20"]


def test_hakrawler_crawl_handler_invocation_wayback_only(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("hakrawler_crawl")

    res = tool.handler(url="https://example.com", forms=False, robots=False, sitemap=False, wayback=True)
    assert res["success"] is True
    assert captured["cmd"] == ["hakrawler", "-url", "https://example.com", "-d", "2", "-subs", "-u"]


def test_osint_category_has_2_tools():
    osint_tools = ToolRegistry.get_by_category("osint")
    assert len(osint_tools) == 2
    names = {t.name for t in osint_tools}
    assert names == {"amass_enum", "hakrawler_crawl"}
