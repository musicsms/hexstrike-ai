from typing import List, Dict, Any

class BaseAgent:
    def __init__(self, name: str, mission: str):
        self.name = name
        self.mission = mission

    def create_recon_plan(self, target: str) -> List[Dict[str, Any]]:
        return [
            {"step": 1, "action": "subdomain_enumeration", "tool": "amass_enum", "target": target},
            {"step": 2, "action": "port_scanning", "tool": "nmap_scan", "target": target},
            {"step": 3, "action": "web_directory_fuzzing", "tool": "ffuf_fuzz", "target": f"http://{target}"}
        ]
