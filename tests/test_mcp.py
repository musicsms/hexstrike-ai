import asyncio
import pytest
from hexstrike.core.registry import ToolRegistry
from hexstrike.mcp.client import HexStrikeClient
from hexstrike.mcp.server import setup_mcp_server
import hexstrike.tools

def test_mcp_client_health():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    assert client.server_url == "http://127.0.0.1:8888"

def test_mcp_server_setup():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    mcp = setup_mcp_server(client)
    assert mcp is not None
    assert mcp.name == "HexStrike AI"

def test_mcp_tools_expose_name_and_description_from_registry():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    mcp = setup_mcp_server(client)

    async def list_tools():
        return await mcp.list_tools()

    tools = asyncio.run(list_tools())
    tools_by_name = {t.name: t for t in tools}

    nmap = ToolRegistry.get("nmap_scan")
    assert nmap.name in tools_by_name
    mcp_tool = tools_by_name[nmap.name]
    assert mcp_tool.description == nmap.description
    assert mcp_tool.description is not None
