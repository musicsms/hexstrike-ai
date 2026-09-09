import argparse
import sys
from fastmcp import FastMCP
from hexstrike.core.config import DEFAULT_HEXSTRIKE_SERVER, COMMAND_TIMEOUT
from hexstrike.core.registry import ToolRegistry
from hexstrike.mcp.client import HexStrikeClient
import hexstrike.tools

def setup_mcp_server(client: HexStrikeClient) -> FastMCP:
    mcp = FastMCP("HexStrike AI")

    for spec in ToolRegistry.get_all_tools():
        tool_name = spec.name
        tool_desc = spec.description
        endpoint = spec.endpoint

        def make_tool(ep):
            def tool_func(**kwargs):
                return client.execute_tool(ep, kwargs)
            return tool_func

        func = make_tool(endpoint)
        func.__name__ = tool_name
        func.__doc__ = tool_desc
        mcp.tool()(func)

    return mcp

def main():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER, help="HexStrike API server URL")
    parser.add_argument("--timeout", type=int, default=COMMAND_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    client = HexStrikeClient(args.server, args.timeout)
    mcp = setup_mcp_server(client)
    mcp.run()

if __name__ == "__main__":
    main()
