import threading
import time as time_module

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

def test_process_registry_tracks_running_process():
    pm = ProcessManager()
    result_holder = {}

    def run():
        result_holder["result"] = pm.execute_command(["sleep", "1"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time_module.sleep(0.3)
    active = pm.list_active_processes()
    assert len(active) == 1
    assert active[0]["command"] == "sleep 1"
    assert active[0]["status"] == "running"
    t.join()
    assert pm.list_active_processes() == []
    assert result_holder["result"]["success"] is True

def test_process_registry_removes_entry_after_timeout():
    pm = ProcessManager()
    result = pm.execute_command(["sleep", "2"], timeout=1, use_cache=False)
    assert result["success"] is False
    assert pm.list_active_processes() == []

def test_get_process_status_unknown_pid_returns_none():
    pm = ProcessManager()
    assert pm.get_process_status(999999) is None

def test_terminate_process_kills_running_command():
    pm = ProcessManager()
    result_holder = {}

    def run():
        result_holder["result"] = pm.execute_command(["sleep", "30"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time_module.sleep(0.3)
    active = pm.list_active_processes()
    assert len(active) == 1
    pid = active[0]["pid"]

    start = time_module.time()
    outcome = pm.terminate_process(pid, timeout=5)
    elapsed = time_module.time() - start

    assert outcome["success"] is True
    assert outcome["method"] == "graceful"
    assert elapsed < 5
    t.join(timeout=5)
    assert result_holder["result"]["success"] is False

def test_terminate_process_unknown_pid():
    pm = ProcessManager()
    assert pm.terminate_process(999999) == {"success": False, "pid": 999999, "method": "not_found"}

def test_pause_and_resume_process():
    pm = ProcessManager()
    result_holder = {}

    def run():
        result_holder["result"] = pm.execute_command(["sleep", "2"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time_module.sleep(0.3)
    pid = pm.list_active_processes()[0]["pid"]

    pause_result = pm.pause_process(pid)
    assert pause_result == {"success": True, "pid": pid}
    assert pm.get_process_status(pid)["status"] == "paused"

    resume_result = pm.resume_process(pid)
    assert resume_result == {"success": True, "pid": pid}
    assert pm.get_process_status(pid)["status"] == "running"
    t.join(timeout=5)

def test_pause_process_on_unknown_pid():
    pm = ProcessManager()
    result = pm.pause_process(999999)
    assert result["success"] is False
