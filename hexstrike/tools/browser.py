from typing import Dict, Any, List, Optional
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import json
import requests
import time
from datetime import datetime
from urllib.parse import urljoin
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

    def run_active_tests(self, page_info: dict, payload: str = '<hexstrikeXSSTest123>') -> dict:
        findings = []
        tested = 0
        for form in page_info.get('forms', []):
            if form.get('method', 'GET').upper() != 'GET':
                continue
            params = []
            for inp in form.get('inputs', [])[:3]:
                if inp.get('type', 'text') in ('text', 'search'):
                    params.append(f"{inp.get('name', 'param')}={payload}")
            if not params:
                continue
            action = form.get('action') or page_info.get('url', '')
            if action.startswith('/'):
                base = page_info.get('url', '')
                try:
                    action = urljoin(base, action)
                except Exception:
                    pass
            test_url = action + ('&' if '?' in action else '?') + '&'.join(params)
            try:
                r = requests.get(test_url, timeout=8, verify=False)
                tested += 1
                if payload in r.text:
                    findings.append({'type': 'reflected_xss', 'severity': 'high', 'description': 'Payload reflected in response', 'url': test_url})
            except Exception:
                continue
            if tested >= 5:
                break
        return {'active_findings': findings, 'tested_forms': tested}

    def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
        try:
            if not self.driver:
                if not self.setup_browser():
                    return {'success': False, 'error': 'Failed to setup browser'}

            self.driver.get(url)
            time.sleep(wait_time)

            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            self.driver.save_screenshot(screenshot_path)
            self.screenshots.append(screenshot_path)

            page_source = self.driver.page_source
            self.page_sources.append({'url': url, 'source': page_source[:50000], 'timestamp': datetime.now().isoformat()})

            page_info = {
                'title': self.driver.title,
                'url': self.driver.current_url,
                'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']} for c in self.driver.get_cookies()],
                'local_storage': self._get_local_storage(),
                'session_storage': self._get_session_storage(),
                'forms': self._extract_forms(),
                'links': self._extract_links(),
                'inputs': self._extract_inputs(),
                'scripts': self._extract_scripts(),
                'network_requests': self._get_network_logs(),
                'console_errors': self._get_console_errors()
            }

            security_analysis = self._analyze_page_security(page_source, page_info)
            extended_passive = self._extended_passive_analysis(page_info, page_source)
            security_analysis['issues'].extend(extended_passive['issues'])
            security_analysis['total_issues'] = len(security_analysis['issues'])
            security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
            security_analysis['passive_modules'] = extended_passive.get('modules', [])

            return {
                'success': True,
                'page_info': page_info,
                'security_analysis': security_analysis,
                'screenshot': screenshot_path,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}


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


@ToolRegistry.register(
    name="browser_navigate",
    category="webtest",
    description="Navigate to a URL with a real browser and inspect the rendered page for security issues",
    endpoint="/api/tools/browser-agent/navigate"
)
def browser_navigate(url: str, headless: bool = True, wait_time: int = 5, proxy_port: Optional[int] = None, active_tests: bool = False) -> Dict[str, Any]:
    if not _browser_agent.driver:
        setup_success = _browser_agent.setup_browser(headless, proxy_port)
        if not setup_success:
            return {"success": False, "error": "Failed to setup browser"}
    result = _browser_agent.navigate_and_inspect(url, wait_time)
    if result.get("success") and active_tests:
        active_results = _browser_agent.run_active_tests(result.get("page_info", {}))
        result["active_tests"] = active_results
    return result


@ToolRegistry.register(
    name="browser_screenshot",
    category="webtest",
    description="Capture a screenshot of the current page in the active browser session",
    endpoint="/api/tools/browser-agent/screenshot"
)
def browser_screenshot() -> Dict[str, Any]:
    if not _browser_agent.driver:
        return {"success": False, "error": "Browser not initialized. Use navigate action first."}
    screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
    _browser_agent.driver.save_screenshot(screenshot_path)
    return {
        "success": True,
        "screenshot": screenshot_path,
        "current_url": _browser_agent.driver.current_url,
        "timestamp": datetime.now().isoformat(),
    }
