import pytest
from hexstrike.mcp.client import HexStrikeClient
from hexstrike.mcp.server import setup_mcp_server

def test_mcp_client_health():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    assert client.server_url == "http://127.0.0.1:8888"

def test_mcp_server_setup():
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    mcp = setup_mcp_server(client)
    assert mcp is not None
    assert mcp.name == "HexStrike AI"
