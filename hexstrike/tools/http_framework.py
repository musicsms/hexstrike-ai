from typing import Dict, Any, Optional, List
import re
import requests
from datetime import datetime
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

    def intercept_request(self, url: str, method: str = 'GET', data: dict = None,
                           headers: dict = None, cookies: dict = None) -> dict:
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)

            if method.upper() == 'GET':
                response = self.session.get(url, params=data, headers=send_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)

            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }

            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }

            self.proxy_history.append({'request': request_data, 'response': response_data})
            self._analyze_response_for_vulns(url, response)

            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _analyze_response_for_vulns(self, url: str, response):
        vulns = []

        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })

        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]

        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]
                })

        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]

        for error in sql_errors:
            if error.lower() in response.text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })

        self.vulnerabilities.extend(vulns)

    def _get_recent_vulns(self, limit: int = 10):
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []

    def send_custom_request(self, request_spec: dict) -> dict:
        url = request_spec.get('url', '')
        method = request_spec.get('method', 'GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)


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


@ToolRegistry.register(
    name="http_framework_request",
    category="webtest",
    description="Intercept and analyze an HTTP request/response for vulnerabilities",
    endpoint="/api/tools/http-framework/request"
)
def http_framework_request(url: str, method: str = "GET", data: Optional[dict] = None, headers: Optional[dict] = None, cookies: Optional[dict] = None) -> Dict[str, Any]:
    return _http_framework.intercept_request(url, method, data, headers, cookies)


@ToolRegistry.register(
    name="http_framework_proxy_history",
    category="webtest",
    description="Retrieve captured HTTP proxy history and vulnerabilities",
    endpoint="/api/tools/http-framework/proxy-history"
)
def http_framework_proxy_history() -> Dict[str, Any]:
    return {
        "success": True,
        "history": _http_framework.proxy_history[-100:],
        "total_requests": len(_http_framework.proxy_history),
        "vulnerabilities": _http_framework.vulnerabilities,
    }


@ToolRegistry.register(
    name="http_framework_repeater",
    category="webtest",
    description="Resend a custom HTTP request with explicit fields",
    endpoint="/api/tools/http-framework/repeater"
)
def http_framework_repeater(request: Optional[dict] = None) -> Dict[str, Any]:
    return _http_framework.send_custom_request(request or {})
