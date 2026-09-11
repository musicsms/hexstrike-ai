import os
import signal
import threading
import time
import subprocess
from typing import List, Dict, Any, Optional
from hexstrike.core.config import COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL

_current_task_id = threading.local()

class ProcessManager:
    def __init__(self, cache_size: int = CACHE_SIZE, cache_ttl: int = CACHE_TTL):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.cache_hits = 0
        self.cache_misses = 0
        self.active_processes: Dict[int, Dict[str, Any]] = {}
        self._registry_lock = threading.RLock()

    def _get_cache_key(self, command: List[str], stdin_input: Optional[str] = None, cwd: Optional[str] = None) -> str:
        key = " ".join(command)
        if stdin_input is not None:
            key += f"\x00{stdin_input}"
        if cwd is not None:
            key += f"\x00cwd={cwd}"
        return key

    def execute_command(self, command: List[str], timeout: int = COMMAND_TIMEOUT, use_cache: bool = True, stdin_input: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
        cmd_str = " ".join(command)
        cache_key = self._get_cache_key(command, stdin_input, cwd)
        now = time.time()

        if use_cache and cache_key in self.cache:
            entry = self.cache[cache_key]
            if now - entry["timestamp"] < self.cache_ttl:
                self.cache_hits += 1
                return {
                    "success": entry["success"],
                    "command": cmd_str,
                    "output": entry["output"],
                    "error": entry.get("error"),
                    "execution_time": "0.00s",
                    "cached": True
                }

        self.cache_misses += 1
        start_time = time.time()
        proc = None
        try:
            popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if stdin_input is not None:
                popen_kwargs["stdin"] = subprocess.PIPE
            if cwd is not None:
                popen_kwargs["cwd"] = cwd
            proc = subprocess.Popen(command, **popen_kwargs)

            with self._registry_lock:
                self.active_processes[proc.pid] = {
                    "pid": proc.pid,
                    "command": cmd_str,
                    "start_time": start_time,
                    "status": "running",
                    "task_id": getattr(_current_task_id, "value", None),
                    "process": proc,
                }

            try:
                try:
                    stdout, stderr = proc.communicate(input=stdin_input, timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    raise
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
                with self._registry_lock:
                    self.active_processes.pop(proc.pid, None)

            elapsed = f"{time.time() - start_time:.2f}s"
            success = (proc.returncode == 0)
            output = stdout
            error = stderr if not success else None

            result_data = {
                "success": success,
                "command": cmd_str,
                "output": output,
                "error": error,
                "execution_time": elapsed,
                "cached": False
            }

            if use_cache and success:
                if len(self.cache) >= self.cache_size:
                    oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["timestamp"])
                    del self.cache[oldest_key]
                self.cache[cache_key] = {
                    "success": success,
                    "output": output,
                    "error": error,
                    "timestamp": now
                }

            return result_data

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": f"Command timed out after {timeout} seconds",
                "execution_time": f"{time.time() - start_time:.2f}s",
                "cached": False
            }
        except Exception as exc:
            return {
                "success": False,
                "command": cmd_str,
                "output": "",
                "error": str(exc),
                "execution_time": f"{time.time() - start_time:.2f}s",
                "cached": False
            }

    def get_cache_stats(self) -> Dict[str, Any]:
        total = self.cache_hits + self.cache_misses
        rate = f"{(self.cache_hits / total * 100):.1f}%" if total > 0 else "0.0%"
        return {
            "size": len(self.cache),
            "max_size": self.cache_size,
            "hits": self.cache_hits,
            "misses": self.cache_misses,
            "hit_rate": rate,
            "evictions": 0
        }

    def list_active_processes(self) -> List[Dict[str, Any]]:
        now = time.time()
        with self._registry_lock:
            return [
                {
                    "pid": pid,
                    "command": entry["command"],
                    "status": entry["status"],
                    "task_id": entry["task_id"],
                    "running_time": now - entry["start_time"],
                }
                for pid, entry in self.active_processes.items()
            ]

    def get_process_status(self, pid: int) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._registry_lock:
            entry = self.active_processes.get(pid)
            if entry is None:
                return None
            return {
                "pid": pid,
                "command": entry["command"],
                "status": entry["status"],
                "task_id": entry["task_id"],
                "running_time": now - entry["start_time"],
            }

    def terminate_process(self, pid: int, timeout: int = 10) -> Dict[str, Any]:
        with self._registry_lock:
            entry = self.active_processes.get(pid)
        if entry is None:
            return {"success": False, "pid": pid, "method": "not_found"}

        entry["process"].terminate()
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._registry_lock:
                if pid not in self.active_processes:
                    return {"success": True, "pid": pid, "method": "graceful"}
            time.sleep(0.1)

        with self._registry_lock:
            still_running = pid in self.active_processes
        if still_running:
            entry["process"].kill()
        return {"success": True, "pid": pid, "method": "forced"}

    def pause_process(self, pid: int) -> Dict[str, Any]:
        if os.name == "nt":
            return {"success": False, "error": "pause/resume is not supported on Windows"}
        with self._registry_lock:
            entry = self.active_processes.get(pid)
        if entry is None:
            return {"success": False, "pid": pid, "error": "process not found"}
        try:
            os.kill(pid, signal.SIGSTOP)
        except ProcessLookupError:
            return {"success": False, "pid": pid, "error": "process not found"}
        with self._registry_lock:
            if pid in self.active_processes:
                self.active_processes[pid]["status"] = "paused"
        return {"success": True, "pid": pid}

    def resume_process(self, pid: int) -> Dict[str, Any]:
        if os.name == "nt":
            return {"success": False, "error": "pause/resume is not supported on Windows"}
        with self._registry_lock:
            entry = self.active_processes.get(pid)
        if entry is None:
            return {"success": False, "pid": pid, "error": "process not found"}
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            return {"success": False, "pid": pid, "error": "process not found"}
        with self._registry_lock:
            if pid in self.active_processes:
                self.active_processes[pid]["status"] = "running"
        return {"success": True, "pid": pid}

default_process_manager = ProcessManager()
