from typing import Dict, Any, Optional, List
import re
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
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

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            h = urlparse(url).hostname or ''
            target = self.scope.get('host', '')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.' + target):
                return True
        except Exception:
            return True
        return False

    def _apply_match_replace(self, url: str, data, headers: dict):
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        if not self._in_scope(url):
            return original_url, data, headers
        return url, out_data, out_headers


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
