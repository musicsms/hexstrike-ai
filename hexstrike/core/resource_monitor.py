import time
from collections import deque
from typing import Dict, Any
import psutil


class ResourceMonitor:
    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self._history: deque = deque(maxlen=history_size)

    def get_current_usage(self) -> Dict[str, Any]:
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            usage = {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024 ** 3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 ** 3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time(),
            }
        except Exception as exc:
            usage = {
                "cpu_percent": 0, "memory_percent": 0, "memory_available_gb": 0,
                "disk_percent": 0, "disk_free_gb": 0, "network_bytes_sent": 0,
                "network_bytes_recv": 0, "timestamp": time.time(), "error": str(exc),
            }
        self._history.append(usage)
        return usage

    def get_usage_trends(self) -> Dict[str, Any]:
        if len(self._history) < 2:
            return {}
        recent = list(self._history)[-10:]
        return {
            "cpu_avg_recent": sum(u["cpu_percent"] for u in recent) / len(recent),
            "memory_avg_recent": sum(u["memory_percent"] for u in recent) / len(recent),
            "measurements": len(self._history),
        }


default_resource_monitor = ResourceMonitor()
