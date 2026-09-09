import pytest
from hexstrike.core.registry import ToolRegistry, ToolSpec

def test_tool_registry_registration():
    ToolRegistry.clear()

    @ToolRegistry.register(
        name="test_tool",
        category="network",
        description="A test tool",
        endpoint="/api/tools/test-tool"
    )
    def dummy_tool(target: str):
        return {"target": target}

    tool = ToolRegistry.get("test_tool")
    assert tool is not None
    assert tool.name == "test_tool"
    assert tool.category == "network"
    assert tool.endpoint == "/api/tools/test-tool"
    assert tool.handler("localhost") == {"target": "localhost"}

def test_tool_registry_get_by_category():
    ToolRegistry.clear()

    @ToolRegistry.register(name="t1", category="web", description="Web tool")
    def t1(): pass

    @ToolRegistry.register(name="t2", category="network", description="Net tool")
    def t2(): pass

    web_tools = ToolRegistry.get_by_category("web")
    assert len(web_tools) == 1
    assert web_tools[0].name == "t1"
