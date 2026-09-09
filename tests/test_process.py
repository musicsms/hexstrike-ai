import pytest
from hexstrike.core.process import ProcessManager

def test_process_manager_execution():
    pm = ProcessManager()
    result = pm.execute_command(["echo", "hexstrike_test"], use_cache=False)
    assert result["success"] is True
    assert "hexstrike_test" in result["output"]
    assert result["cached"] is False

def test_process_manager_caching():
    pm = ProcessManager()
    cmd = ["echo", "cache_me"]
    r1 = pm.execute_command(cmd, use_cache=True)
    r2 = pm.execute_command(cmd, use_cache=True)
    assert r1["cached"] is False
    assert r2["cached"] is True
    assert r2["output"] == r1["output"]

def test_process_manager_timeout():
    pm = ProcessManager()
    result = pm.execute_command(["sleep", "2"], timeout=1, use_cache=False)
    assert result["success"] is False
    assert "timed out" in result["error"].lower()
