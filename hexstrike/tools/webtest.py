from typing import Dict, Any
from datetime import datetime
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.http_framework import _http_framework
from hexstrike.tools.browser import _browser_agent


@ToolRegistry.register(
    name="burpsuite_alternative_scan",
    category="webtest",
    description="Comprehensive web application security scan combining browser recon, HTTP spidering, and vulnerability analysis",
    endpoint="/api/tools/burpsuite-alternative"
)
def burpsuite_alternative_scan(target: str, scan_type: str = "comprehensive", headless: bool = True, max_depth: int = 3, max_pages: int = 50) -> Dict[str, Any]:
    try:
        results: Dict[str, Any] = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }

        browser_opened_by_this_scan = False

        if scan_type in ['comprehensive', 'spider']:
            if not _browser_agent.driver:
                setup_success = _browser_agent.setup_browser(headless)
                if setup_success:
                    browser_opened_by_this_scan = True
                    results['browser_analysis'] = _browser_agent.navigate_and_inspect(target)
                else:
                    results['browser_analysis'] = {'success': False, 'error': 'Failed to setup browser'}
            else:
                results['browser_analysis'] = _browser_agent.navigate_and_inspect(target)

        if scan_type in ['comprehensive', 'spider']:
            spider_result = _http_framework.spider_website(target, max_depth, max_pages)
            results['spider_analysis'] = spider_result

        if scan_type in ['comprehensive', 'active']:
            discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
            vuln_results = []
            for url in discovered_urls[:20]:
                test_result = _http_framework.intercept_request(url)
                if test_result.get('success'):
                    vuln_results.append(test_result)
            results['vulnerability_analysis'] = {
                'tested_urls': len(vuln_results),
                'total_vulnerabilities': len(_http_framework.vulnerabilities),
                'recent_vulnerabilities': _http_framework._get_recent_vulns(20)
            }

        total_vulns = len(_http_framework.vulnerabilities)
        vuln_summary: Dict[str, int] = {}
        for vuln in _http_framework.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'vulnerability_breakdown': vuln_summary,
            'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
            'security_score': max(0, 100 - (total_vulns * 5))
        }

        if browser_opened_by_this_scan:
            _browser_agent.close_browser()

        return results

    except Exception as e:
        return {'success': False, 'error': str(e)}
