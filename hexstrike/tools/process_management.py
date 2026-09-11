from typing import Dict, Any, Optional, Annotated
from pydantic import Field
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
from hexstrike.core.resource_monitor import default_resource_monitor
from hexstrike.core.task_pool import default_task_pool


@ToolRegistry.register(
    name="task_submit",
    category="process",
    description="Run a registered tool in the background and return a task_id immediately instead of blocking until it finishes - poll with task_status. Only tools already in the registry can be submitted, never an arbitrary shell command.",
    endpoint="/api/tools/task-submit"
)
def task_submit(
    tool_name: Annotated[str, Field(description="Name of a registered tool to run, e.g. 'nmap_scan' (must already exist in the tool registry)")],
    params: Annotated[Optional[Dict[str, Any]], Field(description="Keyword arguments to pass to the tool, e.g. {'target': '10.0.0.5'}")] = None,
) -> Dict[str, Any]:
    return default_task_pool.submit(tool_name, params or {})


@ToolRegistry.register(
    name="task_status",
    category="process",
    description="Check the status of a task submitted via task_submit: queued, running, completed (with result), failed (with error), or cancelled",
    endpoint="/api/tools/task-status"
)
def task_status(
    task_id: Annotated[str, Field(description="task_id returned by task_submit")],
) -> Dict[str, Any]:
    return default_task_pool.get_status(task_id)


@ToolRegistry.register(
    name="task_list",
    category="process",
    description="List all tasks submitted via task_submit in this server process, with their current status",
    endpoint="/api/tools/task-list"
)
def task_list() -> Dict[str, Any]:
    return default_task_pool.list_tasks()


@ToolRegistry.register(
    name="task_terminate",
    category="process",
    description="Cancel a queued task, or kill the OS subprocess(es) a running task spawned. A running task's status settles to 'completed' (with result.success == False) shortly after this call, not instantly - it is not force-killed synchronously.",
    endpoint="/api/tools/task-terminate"
)
def task_terminate(
    task_id: Annotated[str, Field(description="task_id returned by task_submit")],
) -> Dict[str, Any]:
    return default_task_pool.terminate(task_id)


@ToolRegistry.register(
    name="process_list",
    category="process",
    description="List every subprocess currently running through this server, from any tool call (synchronous or via task_submit), with PID, command, and running time",
    endpoint="/api/tools/process-list"
)
def process_list() -> Dict[str, Any]:
    return {"success": True, "processes": default_process_manager.list_active_processes()}


@ToolRegistry.register(
    name="process_status",
    category="process",
    description="Get the status of one running subprocess by PID (see process_list)",
    endpoint="/api/tools/process-status"
)
def process_status(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    status = default_process_manager.get_process_status(pid)
    if status is None:
        return {"success": False, "error": f"No active process with pid {pid}"}
    return {"success": True, **status}


@ToolRegistry.register(
    name="process_terminate",
    category="process",
    description="Terminate a running subprocess by PID - SIGTERM first, SIGKILL if it hasn't exited within 10 seconds",
    endpoint="/api/tools/process-terminate"
)
def process_terminate(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    return default_process_manager.terminate_process(pid)


@ToolRegistry.register(
    name="process_pause",
    category="process",
    description="Pause a running subprocess by PID via SIGSTOP - POSIX only, fails on Windows",
    endpoint="/api/tools/process-pause"
)
def process_pause(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    return default_process_manager.pause_process(pid)


@ToolRegistry.register(
    name="process_resume",
    category="process",
    description="Resume a paused subprocess by PID via SIGCONT - POSIX only, fails on Windows",
    endpoint="/api/tools/process-resume"
)
def process_resume(
    pid: Annotated[int, Field(description="Process ID, from process_list")],
) -> Dict[str, Any]:
    return default_process_manager.resume_process(pid)


@ToolRegistry.register(
    name="system_resource_usage",
    category="process",
    description="Snapshot of current CPU/memory/disk/network usage on the machine running this server, plus a short rolling trend",
    endpoint="/api/tools/system-resource-usage"
)
def system_resource_usage() -> Dict[str, Any]:
    return {
        "success": True,
        "usage": default_resource_monitor.get_current_usage(),
        "trends": default_resource_monitor.get_usage_trends(),
    }


@ToolRegistry.register(
    name="system_telemetry",
    category="process",
    description="Aggregate execution statistics across every tool call this server has handled: total commands, success rate, average execution time, uptime",
    endpoint="/api/tools/system-telemetry"
)
def system_telemetry() -> Dict[str, Any]:
    return {"success": True, **default_process_manager.get_telemetry_stats()}
