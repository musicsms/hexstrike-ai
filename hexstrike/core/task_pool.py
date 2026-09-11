import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.config import TASK_POOL_MAX_WORKERS
from hexstrike.core.process import _current_task_id, default_process_manager


class TaskPool:
    def __init__(self, max_workers: int = TASK_POOL_MAX_WORKERS):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def submit(self, tool_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        spec = ToolRegistry.get(tool_name)
        if spec is None:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        task_id = str(uuid.uuid4())
        call_params = params or {}

        def run():
            _current_task_id.value = task_id
            try:
                return spec.handler(**call_params)
            finally:
                _current_task_id.value = None

        future = self._executor.submit(run)
        with self._lock:
            self._tasks[task_id] = {
                "tool_name": tool_name,
                "params": call_params,
                "submitted_at": time.time(),
                "future": future,
            }
            self._prune_old_completed()
        return {"success": True, "task_id": task_id}

    def _task_view(self, task_id: str, entry: Dict[str, Any]) -> Dict[str, Any]:
        future = entry["future"]
        view = {
            "task_id": task_id,
            "tool_name": entry["tool_name"],
            "submitted_at": entry["submitted_at"],
            "elapsed_seconds": time.time() - entry["submitted_at"],
        }
        if future.cancelled():
            view["status"] = "cancelled"
        elif future.done():
            exc = future.exception()
            if exc is not None:
                view["status"] = "failed"
                view["error"] = str(exc)
            else:
                view["status"] = "completed"
                view["result"] = future.result()
        elif future.running():
            view["status"] = "running"
        else:
            view["status"] = "queued"
        return view

    def get_status(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            entry = self._tasks.get(task_id)
        if entry is None:
            return {"success": False, "error": f"Unknown task_id: {task_id}"}
        return {"success": True, **self._task_view(task_id, entry)}

    def list_tasks(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._tasks.items())
        return {"success": True, "tasks": [self._task_view(tid, e) for tid, e in items]}

    def terminate(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            entry = self._tasks.get(task_id)
        if entry is None:
            return {"success": False, "error": f"Unknown task_id: {task_id}"}

        future = entry["future"]
        if future.cancel():
            return {"success": True, "task_id": task_id, "status": "cancelled"}
        if future.done():
            return {"success": True, "task_id": task_id, "status": self._task_view(task_id, entry)["status"]}

        killed = []
        for proc_info in default_process_manager.list_active_processes():
            if proc_info["task_id"] == task_id:
                default_process_manager.terminate_process(proc_info["pid"])
                killed.append(proc_info["pid"])
        return {"success": True, "task_id": task_id, "status": "termination_requested", "killed_pids": killed}

    def _prune_old_completed(self, max_completed: int = 500) -> None:
        completed = [(tid, e) for tid, e in self._tasks.items() if e["future"].done()]
        if len(completed) <= max_completed:
            return
        completed.sort(key=lambda item: item[1]["submitted_at"])
        for tid, _ in completed[: len(completed) - max_completed]:
            del self._tasks[tid]


default_task_pool = TaskPool()
