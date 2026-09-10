from typing import Dict, Any, Optional, List
import requests
from hexstrike.core.registry import ToolRegistry


class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.match_replace_rules: List[Dict[str, Any]] = []
        self.scope: Optional[Dict[str, Any]] = None
        self._req_id = 0

    def reset(self):
        """Test-only: clear all accumulated state. Never called by production tool functions."""
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []
        self.scope = None
        self._req_id = 0

    def set_match_replace_rules(self, rules: list):
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}


_http_framework = HTTPTestingFramework()


@ToolRegistry.register(
    name="http_framework_set_rules",
    category="webtest",
    description="Configure HTTP request/response match-replace rules",
    endpoint="/api/tools/http-framework/set-rules"
)
def http_framework_set_rules(rules: Optional[list] = None) -> Dict[str, Any]:
    _http_framework.set_match_replace_rules(rules)
    return {"success": True, "rules_set": len(rules or [])}


@ToolRegistry.register(
    name="http_framework_set_scope",
    category="webtest",
    description="Restrict HTTP framework testing to a host scope",
    endpoint="/api/tools/http-framework/set-scope"
)
def http_framework_set_scope(host: str, include_subdomains: bool = True) -> Dict[str, Any]:
    _http_framework.set_scope(host, include_subdomains)
    return {"success": True, "scope": _http_framework.scope}
