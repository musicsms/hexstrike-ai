from typing import Dict, Any, List, Optional
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import json
import requests
from hexstrike.core.registry import ToolRegistry


class BrowserAgent:
    """AI-powered browser agent for web application testing and inspection"""

    def __init__(self):
        self.driver = None
        self.screenshots: List[str] = []
        self.page_sources: List[Dict[str, Any]] = []
        self.network_logs: List[Dict[str, Any]] = []

    def reset(self):
        """Test-only: clear all accumulated state and close any real browser. Never called by production tool functions."""
        self.close_browser()
        self.screenshots = []
        self.page_sources = []
        self.network_logs = []

    def setup_browser(self, headless: bool = True, proxy_port: Optional[int] = None) -> bool:
        try:
            chrome_options = Options()
            if headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=HexStrike-BrowserAgent/1.0 (Security Testing)')
            chrome_options.add_argument('--enable-logging')
            chrome_options.add_argument('--log-level=0')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            if proxy_port:
                chrome_options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')
            chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            return True
        except Exception:
            return False

    def close_browser(self):
        if self.driver:
            self.driver.quit()
            self.driver = None

    def _get_console_errors(self) -> list:
        try:
            logs = self.driver.get_log('browser')
            out = []
            for entry in logs[-100:]:
                lvl = entry.get('level', '')
                if lvl in ('SEVERE', 'WARNING'):
                    out.append({'level': lvl, 'message': entry.get('message', '')[:500]})
            return out
        except Exception:
            return []

    def _get_local_storage(self) -> dict:
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
        except Exception:
            return {}

    def _get_session_storage(self) -> dict:
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
        except Exception:
            return {}

    def _extract_forms(self) -> list:
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }
                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })
                forms.append(form_data)
        except Exception:
            pass
        return forms

    def _extract_links(self) -> list:
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in link_elements[:50]:
                href = link.get_attribute('href')
                if href:
                    links.append({'href': href, 'text': link.text[:100]})
        except Exception:
            pass
        return links

    def _extract_inputs(self) -> list:
        inputs = []
        try:
            input_elements = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
        except Exception:
            pass
        return inputs

    def _extract_scripts(self) -> list:
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in script_elements[:20]:
                src = script.get_attribute('src')
                if src:
                    scripts.append({'type': 'external', 'src': src})
                else:
                    content = script.get_attribute('innerHTML')
                    if content and len(content) > 10:
                        scripts.append({'type': 'inline', 'content': content[:1000]})
        except Exception:
            pass
        return scripts

    def _get_network_logs(self) -> list:
        try:
            logs = self.driver.get_log('performance')
            network_requests = []
            for log in logs[-50:]:
                message = json.loads(log['message'])
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_requests.append({
                        'url': response['url'],
                        'status': response['status'],
                        'mimeType': response['mimeType'],
                        'headers': response.get('headers', {})
                    })
            return network_requests
        except Exception:
            return []

    def _analyze_page_security(self, page_source: str, page_info: dict) -> dict:
        issues = []

        for storage_type, storage_data in [('localStorage', page_info.get('local_storage', {})),
                                            ('sessionStorage', page_info.get('session_storage', {}))]:
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    issues.append({
                        'type': 'sensitive_data_storage',
                        'severity': 'high',
                        'description': f'Sensitive data found in {storage_type}: {key}',
                        'location': storage_type
                    })

        for form in page_info.get('forms', []):
            has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower()
                          for input_data in form['inputs'])
            if not has_csrf and form['method'].upper() == 'POST':
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'description': 'Form without CSRF protection detected',
                    'form_action': form['action']
                })

        inline_scripts = [s for s in page_info.get('scripts', []) if s['type'] == 'inline']
        if inline_scripts:
            issues.append({
                'type': 'inline_javascript',
                'severity': 'low',
                'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                'count': len(inline_scripts)
            })

        return {
            'total_issues': len(issues),
            'issues': issues,
            'security_score': max(0, 100 - (len(issues) * 10))
        }

    def _analyze_cookies(self, cookies: list) -> list:
        issues = []
        for ck in cookies:
            name = ck.get('name', '')
            if name.lower() in ('sessionid', 'phpsessid', 'jsessionid') and len(ck.get('value', '')) < 16:
                issues.append({'type': 'weak_session_cookie', 'severity': 'medium', 'description': f'Session cookie {name} appears short'})
        return issues

    def _analyze_security_headers(self, page_source: str, page_info: dict) -> list:
        issues = []
        try:
            resp = requests.get(page_info.get('url', ''), timeout=10, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            required = {
                'content-security-policy': 'CSP header missing (XSS mitigation)',
                'x-frame-options': 'X-Frame-Options missing (Clickjacking risk)',
                'x-content-type-options': 'X-Content-Type-Options missing (MIME sniffing risk)',
                'referrer-policy': 'Referrer-Policy missing (leaky referrers)',
                'strict-transport-security': 'HSTS missing (HTTPS downgrade risk)'
            }
            for key, desc in required.items():
                if key not in headers:
                    issues.append({'type': 'missing_security_header', 'severity': 'medium', 'description': desc, 'header': key})
            csp = headers.get('content-security-policy', '')
            if csp and "unsafe-inline" in csp:
                issues.append({'type': 'weak_csp', 'severity': 'low', 'description': 'CSP allows unsafe-inline scripts'})
        except Exception:
            pass
        return issues

    def _detect_mixed_content(self, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url', '')
            if page_url.startswith('https://'):
                for req in page_info.get('network_requests', [])[:200]:
                    u = req.get('url', '')
                    if u.startswith('http://'):
                        issues.append({'type': 'mixed_content', 'severity': 'medium', 'description': f'HTTP resource loaded over HTTPS page: {u[:100]}'})
        except Exception:
            pass
        return issues

    def _extended_passive_analysis(self, page_info: dict, page_source: str) -> dict:
        modules = []
        issues = []
        cookie_issues = self._analyze_cookies(page_info.get('cookies', []))
        if cookie_issues:
            issues.extend(cookie_issues); modules.append('cookie_analysis')
        header_issues = self._analyze_security_headers(page_source, page_info)
        if header_issues:
            issues.extend(header_issues); modules.append('security_headers')
        mixed = self._detect_mixed_content(page_info)
        if mixed:
            issues.extend(mixed); modules.append('mixed_content')
        if page_info.get('console_errors'):
            modules.append('console_log_capture')
        return {'issues': issues, 'modules': modules}


_browser_agent = BrowserAgent()


@ToolRegistry.register(
    name="browser_close",
    category="webtest",
    description="Close the active browser session",
    endpoint="/api/tools/browser-agent/close"
)
def browser_close() -> Dict[str, Any]:
    _browser_agent.close_browser()
    return {"success": True, "message": "Browser closed successfully"}


@ToolRegistry.register(
    name="browser_status",
    category="webtest",
    description="Report whether a browser session is active and basic session stats",
    endpoint="/api/tools/browser-agent/status"
)
def browser_status() -> Dict[str, Any]:
    return {
        "success": True,
        "browser_active": _browser_agent.driver is not None,
        "screenshots_taken": len(_browser_agent.screenshots),
        "pages_visited": len(_browser_agent.page_sources),
    }
