import argparse
import sys
import functools
import inspect
from fastmcp import FastMCP
from hexstrike.core.config import DEFAULT_HEXSTRIKE_SERVER, COMMAND_TIMEOUT
from hexstrike.core.logging_config import configure_logging
from hexstrike.core.registry import ToolRegistry
from hexstrike.mcp.client import HexStrikeClient
import hexstrike.tools

def setup_mcp_server(client: HexStrikeClient) -> FastMCP:
    mcp = FastMCP("HexStrike AI")

    for spec in ToolRegistry.get_all_tools():
        tool_name = spec.name
        tool_desc = spec.description
        endpoint = spec.endpoint
        handler = spec.handler

        def make_tool(func, ep):
            handler_sig = inspect.signature(func)
            # Expose use_recovery as an extra, optional parameter in the
            # MCP tool schema, on top of the handler's own real signature —
            # the API's own default (True, matching the legacy monolith)
            # applies when a caller doesn't set it, so it's only forwarded
            # when explicitly given.
            exposed_sig = handler_sig.replace(parameters=[
                *handler_sig.parameters.values(),
                inspect.Parameter("use_recovery", inspect.Parameter.KEYWORD_ONLY, default=False, annotation=bool),
            ])

            @functools.wraps(func)
            def tool_func(*args, **kwargs):
                use_recovery = kwargs.pop("use_recovery", False)
                bound = handler_sig.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
                if use_recovery:
                    arguments["use_recovery"] = True
                return client.execute_tool(ep, arguments)

            tool_func.__signature__ = exposed_sig
            return tool_func

        wrapped = make_tool(handler, endpoint)
        mcp.tool(name=tool_name, description=tool_desc)(wrapped)

    return mcp

def main():
    configure_logging()
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
