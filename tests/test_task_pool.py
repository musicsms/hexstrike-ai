import time
import pytest
from hexstrike.core.task_pool import TaskPool
from hexstrike.core.registry import ToolRegistry, ToolSpec


def _register_temp_tool(monkeypatch, name, handler):
    monkeypatch.setitem(
        ToolRegistry._tools, name,
        ToolSpec(name=name, category="test", description="test", endpoint=f"/test/{name}", handler=handler),
    )


def test_submit_unknown_tool_returns_error_without_creating_task():
    pool = TaskPool(max_workers=2)
    result = pool.submit("does_not_exist", {})
    assert result == {"success": False, "error": "Unknown tool: does_not_exist"}


def test_submit_and_poll_to_completion(monkeypatch):
    def add(a, b):
        return {"success": True, "sum": a + b}
    _register_temp_tool(monkeypatch, "test_add_tool", add)

    pool = TaskPool(max_workers=2)
    submitted = pool.submit("test_add_tool", {"a": 2, "b": 3})
    assert submitted["success"] is True
    task_id = submitted["task_id"]

    deadline = time.time() + 5
    status = pool.get_status(task_id)
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.05)
        status = pool.get_status(task_id)

    assert status["status"] == "completed"
    assert status["result"] == {"success": True, "sum": 5}
    pool._executor.shutdown(wait=True)


def test_get_status_unknown_task_id():
    pool = TaskPool(max_workers=2)
    result = pool.get_status("does-not-exist")
    assert result == {"success": False, "error": "Unknown task_id: does-not-exist"}


def test_failed_task_reports_error(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")
    _register_temp_tool(monkeypatch, "test_boom_tool", boom)

    pool = TaskPool(max_workers=2)
    task_id = pool.submit("test_boom_tool", {})["task_id"]

    deadline = time.time() + 5
    status = pool.get_status(task_id)
    while status["status"] in ("queued", "running") and time.time() < deadline:
        time.sleep(0.05)
        status = pool.get_status(task_id)

    assert status["status"] == "failed"
    assert "kaboom" in status["error"]
    pool._executor.shutdown(wait=True)


def test_list_tasks_includes_submitted_task(monkeypatch):
    def add(a, b):
        return {"success": True, "sum": a + b}
    _register_temp_tool(monkeypatch, "test_add_tool_2", add)

    pool = TaskPool(max_workers=2)
    task_id = pool.submit("test_add_tool_2", {"a": 1, "b": 1})["task_id"]
    listing = pool.list_tasks()
    assert listing["success"] is True
    assert any(t["task_id"] == task_id for t in listing["tasks"])
    pool._executor.shutdown(wait=True)


def test_list_tasks_omits_result_and_error_but_get_status_includes_them(monkeypatch):
    def add(a, b):
        return {"success": True, "sum": a + b}
    _register_temp_tool(monkeypatch, "test_add_tool_list_view", add)

    def boom():
        raise RuntimeError("kaboom")
    _register_temp_tool(monkeypatch, "test_boom_tool_list_view", boom)

    pool = TaskPool(max_workers=2)
    ok_id = pool.submit("test_add_tool_list_view", {"a": 4, "b": 5})["task_id"]
    fail_id = pool.submit("test_boom_tool_list_view", {})["task_id"]

    deadline = time.time() + 5
    while (
        pool.get_status(ok_id)["status"] in ("queued", "running")
        or pool.get_status(fail_id)["status"] in ("queued", "running")
    ) and time.time() < deadline:
        time.sleep(0.05)

    # get_status keeps the full payload for a single, specifically-requested task.
    ok_status = pool.get_status(ok_id)
    assert ok_status["status"] == "completed"
    assert ok_status["result"] == {"success": True, "sum": 9}

    fail_status = pool.get_status(fail_id)
    assert fail_status["status"] == "failed"
    assert "kaboom" in fail_status["error"]

    # list_tasks strips result/error to avoid serializing large payloads for
    # every completed/failed task on every call.
    listing = pool.list_tasks()
    assert listing["success"] is True
    by_id = {t["task_id"]: t for t in listing["tasks"]}

    assert by_id[ok_id]["status"] == "completed"
    assert "result" not in by_id[ok_id]

    assert by_id[fail_id]["status"] == "failed"
    assert "error" not in by_id[fail_id]

    pool._executor.shutdown(wait=True)


def test_terminate_queued_task_cancels_it(monkeypatch):
    def blocker():
        time.sleep(2)
        return {"success": True}
    _register_temp_tool(monkeypatch, "test_blocker_tool", blocker)

    pool = TaskPool(max_workers=1)
    first = pool.submit("test_blocker_tool", {})["task_id"]   # occupies the only worker
    second = pool.submit("test_blocker_tool", {})["task_id"]  # stays queued

    result = pool.terminate(second)
    assert result["status"] == "cancelled"
    assert pool.get_status(second)["status"] == "cancelled"
    pool._executor.shutdown(wait=False)


def test_tasks_run_concurrently_not_serially(monkeypatch):
    def sleep_tool(delay):
        time.sleep(delay)
        return {"success": True, "slept": delay}
    _register_temp_tool(monkeypatch, "test_sleep_tool", sleep_tool)

    pool = TaskPool(max_workers=5)
    start = time.time()
    task_ids = [pool.submit("test_sleep_tool", {"delay": 1.0})["task_id"] for _ in range(3)]

    deadline = time.time() + 5
    while any(pool.get_status(tid)["status"] in ("queued", "running") for tid in task_ids) and time.time() < deadline:
        time.sleep(0.05)
    elapsed = time.time() - start

    assert all(pool.get_status(tid)["status"] == "completed" for tid in task_ids)
    assert elapsed < 2.0  # would be ~3s if run serially
    pool._executor.shutdown(wait=True)


def test_terminate_running_task_kills_underlying_process(monkeypatch):
    from hexstrike.core.process import default_process_manager

    def run_sleep():
        return default_process_manager.execute_command(["sleep", "10"], use_cache=False)
    _register_temp_tool(monkeypatch, "test_run_sleep_tool", run_sleep)

    pool = TaskPool(max_workers=2)
    task_id = pool.submit("test_run_sleep_tool", {})["task_id"]
    time.sleep(0.3)  # let the subprocess actually start and register

    result = pool.terminate(task_id)
    assert result["status"] == "termination_requested"
    assert len(result["killed_pids"]) == 1

    deadline = time.time() + 5
    status = pool.get_status(task_id)
    while status["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)
        status = pool.get_status(task_id)
    assert status["status"] == "completed"
    assert status["result"]["success"] is False
    pool._executor.shutdown(wait=True)


def test_submit_rejects_once_max_tracked_tasks_reached(monkeypatch):
    def blocker():
        time.sleep(2)
        return {"success": True}
    _register_temp_tool(monkeypatch, "test_cap_blocker_tool", blocker)

    pool = TaskPool(max_workers=1, max_tracked_tasks=3)
    for _ in range(3):
        result = pool.submit("test_cap_blocker_tool", {})
        assert result["success"] is True

    # The 4th submission must be rejected without creating a task entry,
    # since queued + running + completed already equals the cap.
    rejected = pool.submit("test_cap_blocker_tool", {})
    assert rejected == {"success": False, "error": "Task queue is full, try again later"}
    assert len(pool._tasks) == 3

    pool._executor.shutdown(wait=False)


def test_old_completed_tasks_eventually_pruned_automatically(monkeypatch):
    def quick():
        return {"success": True}
    _register_temp_tool(monkeypatch, "test_quick_tool", quick)

    # _prune_old_completed only runs automatically every 50th submit() call
    # and only actually deletes anything once completed tasks exceed its
    # default retention of 500. Submit enough fast-completing tasks (with
    # small pauses so completions land before later submits run their
    # periodic prune check) to drive completed count past 500 and confirm
    # the periodic trigger prunes it back down rather than growing forever.
    pool = TaskPool(max_workers=8, max_tracked_tasks=100_000)

    submitted_ids = []
    for i in range(600):
        result = pool.submit("test_quick_tool", {})
        assert result["success"] is True
        submitted_ids.append(result["task_id"])
        if i % 20 == 0:
            time.sleep(0.02)  # let the executor drain so tasks actually complete

    # Some early task_ids may already have been pruned away by the periodic
    # trigger by this point -- that's the very behavior under test, so treat
    # a since-pruned id (get_status returns no "status" key) as done, not
    # still queued/running.
    deadline = time.time() + 15
    while any(pool.get_status(tid).get("status") in ("queued", "running") for tid in submitted_ids) and time.time() < deadline:
        time.sleep(0.05)

    # One more submit to make sure a periodic prune checkpoint runs after
    # all 600 tasks have completed.
    for _ in range(50):
        pool.submit("test_quick_tool", {})

    with pool._lock:
        remaining = len(pool._tasks)

    assert remaining < 650  # would be ~650 without any pruning ever kicking in
    pool._executor.shutdown(wait=True)
