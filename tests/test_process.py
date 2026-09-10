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

def test_process_manager_stdin_input():
    pm = ProcessManager()
    result = pm.execute_command(["cat"], stdin_input="hello from stdin\n", use_cache=False)
    assert result["success"] is True
    assert result["output"] == "hello from stdin\n"

def test_process_manager_stdin_input_cache_key_does_not_collide():
    pm = ProcessManager()
    r1 = pm.execute_command(["cat"], stdin_input="first\n", use_cache=True)
    r2 = pm.execute_command(["cat"], stdin_input="second\n", use_cache=True)
    assert r1["output"] == "first\n"
    assert r2["output"] == "second\n"
    assert r2["cached"] is False

def test_process_manager_cwd():
    pm = ProcessManager()
    result = pm.execute_command(["pwd"], cwd="/tmp", use_cache=False)
    assert result["success"] is True
    assert result["output"].strip() == "/tmp"

def test_process_manager_cwd_cache_key_does_not_collide():
    pm = ProcessManager()
    r1 = pm.execute_command(["pwd"], cwd="/tmp", use_cache=True)
    r2 = pm.execute_command(["pwd"], cwd="/", use_cache=True)
    assert r1["output"].strip() == "/tmp"
    assert r2["output"].strip() == "/"
    assert r2["cached"] is False
