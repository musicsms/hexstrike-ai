import pytest
from hexstrike.core.registry import ToolRegistry
from hexstrike.agents.base_agent import BaseAgent
import hexstrike.tools

def test_expanded_tools_registered():
    hydra = ToolRegistry.get("hydra_attack")
    assert hydra is not None
    assert hydra.category == "password"

    amass = ToolRegistry.get("amass_enum")
    assert amass is not None
    assert amass.category == "osint"

def test_base_agent_execution_plan():
    agent = BaseAgent(name="TestAgent", mission="Recon")
    plan = agent.create_recon_plan(target="example.com")
    assert len(plan) >= 2
    assert plan[0]["action"] == "subdomain_enumeration"
