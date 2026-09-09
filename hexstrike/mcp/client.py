import requests
from typing import Dict, Any

class HexStrikeClient:
    def __init__(self, server_url: str, timeout: int = 300):
        self.server_url = server_url.rstrip('/')
        self.timeout = timeout

    def check_health(self) -> Dict[str, Any]:
        try:
            res = requests.get(f"{self.server_url}/health", timeout=5)
            if res.status_code == 200:
                return res.json()
            return {"error": f"Server returned status {res.status_code}"}
        except Exception as exc:
            return {"error": str(exc)}

    def execute_tool(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        try:
            res = requests.post(url, json=params, timeout=self.timeout)
            return res.json()
        except Exception as exc:
            return {"success": False, "error": str(exc)}
