import time
import subprocess
from typing import List, Dict, Any, Optional
from hexstrike.core.config import COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL

class ProcessManager:
    def __init__(self, cache_size: int = CACHE_SIZE, cache_ttl: int = CACHE_TTL):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.cache_hits = 0
        self.cache_misses = 0

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
        try:
            run_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            if stdin_input is not None:
                run_kwargs["input"] = stdin_input
            if cwd is not None:
                run_kwargs["cwd"] = cwd
            res = subprocess.run(command, **run_kwargs)
            elapsed = f"{time.time() - start_time:.2f}s"
            success = (res.returncode == 0)
            output = res.stdout
            error = res.stderr if not success else None

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

default_process_manager = ProcessManager()
