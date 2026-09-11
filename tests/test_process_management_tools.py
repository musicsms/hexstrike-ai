import time
import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools


def test_process_category_has_11_tools():
    tools = ToolRegistry.get_by_category("process")
    assert len(tools) == 11
    names = {t.name for t in tools}
    assert names == {
        "task_submit", "task_status", "task_list", "task_terminate",
        "process_list", "process_status", "process_terminate",
        "process_pause", "process_resume",
        "system_resource_usage", "system_telemetry",
    }


def test_task_submit_and_status_round_trip():
    submit_tool = ToolRegistry.get("task_submit")
    status_tool = ToolRegistry.get("task_status")

    submitted = submit_tool.handler(tool_name="strings_scan", params={"file_path": "/etc/hostname"})
    assert submitted["success"] is True
    task_id = submitted["task_id"]

    deadline = time.time() + 5
    status = status_tool.handler(task_id=task_id)
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.05)
        status = status_tool.handler(task_id=task_id)

    assert status["status"] == "completed"
    assert status["result"]["success"] is True


def test_task_submit_unknown_tool():
    submit_tool = ToolRegistry.get("task_submit")
    result = submit_tool.handler(tool_name="not_a_real_tool")
    assert result["success"] is False


def test_task_status_unknown_id():
    status_tool = ToolRegistry.get("task_status")
    result = status_tool.handler(task_id="nope")
    assert result["success"] is False


def test_task_list_returns_tasks():
    list_tool = ToolRegistry.get("task_list")
    result = list_tool.handler()
    assert result["success"] is True
    assert isinstance(result["tasks"], list)


def test_process_list_and_status_and_terminate(monkeypatch):
    from hexstrike.core.process import default_process_manager
    import threading

    def run():
        default_process_manager.execute_command(["sleep", "5"], use_cache=False)

    t = threading.Thread(target=run)
    t.start()
    time.sleep(0.3)

    list_tool = ToolRegistry.get("process_list")
    listing = list_tool.handler()
    assert listing["success"] is True
    assert len(listing["processes"]) == 1
    pid = listing["processes"][0]["pid"]

    status_tool = ToolRegistry.get("process_status")
    status = status_tool.handler(pid=pid)
    assert status["success"] is True
    assert status["pid"] == pid

    terminate_tool = ToolRegistry.get("process_terminate")
    result = terminate_tool.handler(pid=pid)
    assert result["success"] is True
    t.join(timeout=5)


def test_process_status_unknown_pid():
    status_tool = ToolRegistry.get("process_status")
    result = status_tool.handler(pid=999999)
    assert result["success"] is False


def test_system_resource_usage_tool():
    tool = ToolRegistry.get("system_resource_usage")
    result = tool.handler()
    assert result["success"] is True
    assert "cpu_percent" in result["usage"]


def test_system_telemetry_tool():
    tool = ToolRegistry.get("system_telemetry")
    result = tool.handler()
    assert result["success"] is True
    assert "commands_executed" in result
