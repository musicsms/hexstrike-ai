import base64
import json
from typing import Dict, Any, List, Optional, Annotated
from pydantic import Field
import requests
from hexstrike.core.registry import ToolRegistry
from hexstrike.tools.base import run_tool_command, resolve_binary

@ToolRegistry.register(
    name="ffuf_fuzz",
    category="web",
    description="Fast, general-purpose web fuzzer using ffuf - fuzzes any request position (paths, params, headers, host), not limited to directory discovery",
    endpoint="/api/tools/ffuf"
)
def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["ffuf", "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="gobuster_dir",
    category="web",
    description="Directory and DNS busting using Gobuster - simple, fast wordlist-based brute-forcing; good default when you don't need recursion or extension-aware wordlists",
    endpoint="/api/tools/gobuster"
)
def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="sqlmap_scan",
    category="web",
    description="Automated SQL injection scanner using SQLMap",
    endpoint="/api/tools/sqlmap"
)
def sqlmap_scan(url: str, batch: bool = True, timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["sqlmap", "-u", url]
    if batch:
        cmd.append("--batch")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="arjun_scan",
    category="web",
    description="HTTP parameter discovery using Arjun",
    endpoint="/api/tools/arjun"
)
def arjun_scan(url: str, method: str = "GET", wordlist: Optional[str] = None, delay: int = 0, threads: int = 25, stable: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["arjun", "-u", url, "-m", method, "-t", str(threads)]
    if wordlist:
        cmd.extend(["-w", wordlist])
    if delay > 0:
        cmd.extend(["-d", str(delay)])
    if stable:
        cmd.append("--stable")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dalfox_scan",
    category="web",
    description="Advanced XSS vulnerability scanning using Dalfox - fast parameter mining plus reflected/DOM XSS detection; the default choice for URL-based XSS testing",
    endpoint="/api/tools/dalfox"
)
def dalfox_scan(url: Optional[str] = None, pipe_mode: bool = False, blind: bool = False, mining_dom: bool = True, mining_dict: bool = True, custom_payload: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    if pipe_mode:
        cmd = ["dalfox", "pipe"]
    else:
        cmd = ["dalfox", "url", url]
    if blind:
        cmd.append("--blind")
    if mining_dom:
        cmd.append("--mining-dom")
    if mining_dict:
        cmd.append("--mining-dict")
    if custom_payload:
        cmd.extend(["--custom-payload", custom_payload])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="dirb_scan",
    category="web",
    description="Directory and file brute-forcing using dirb - recursive by default; the classic, simplest option, slower than ffuf/feroxbuster on large wordlists",
    endpoint="/api/tools/dirb"
)
def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dirb", url, wordlist]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="dirsearch_scan",
    category="web",
    description="Advanced directory and file discovery using Dirsearch - extension-aware wordlists with recursion; a strong default choice for thorough content discovery",
    endpoint="/api/tools/dirsearch"
)
def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json", wordlist: str = "/usr/share/wordlists/dirsearch/common.txt", threads: int = 30, recursive: bool = False, timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["dirsearch", "-u", url, "-e", extensions, "-w", wordlist, "-t", str(threads)]
    if recursive:
        cmd.append("-r")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="dotdotpwn_scan",
    category="web",
    description="Directory traversal fuzzing using DotDotPwn",
    endpoint="/api/tools/dotdotpwn"
)
def dotdotpwn_scan(
    target: str,
    module: Annotated[str, Field(description="DotDotPwn protocol module to test path traversal against, e.g. 'http', 'ftp', 'tftp', 'payload'")] = "http",
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["dotdotpwn", "-m", module, "-h", target]
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append("-b")
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="feroxbuster_scan",
    category="web",
    description="Recursive content discovery using Feroxbuster - Rust-based, the fastest option here for large-scale recursive scans",
    endpoint="/api/tools/feroxbuster"
)
def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10, timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "-t", str(threads)]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="gau_discover",
    category="web",
    description="URL discovery from multiple archive sources using Gau",
    endpoint="/api/tools/gau"
)
def gau_discover(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan", include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["gau", domain]
    if providers != "wayback,commoncrawl,otx,urlscan":
        cmd.extend(["--providers", providers])
    if include_subs:
        cmd.append("--subs")
    if blacklist:
        cmd.extend(["--blacklist", blacklist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="httpx_probe",
    category="web",
    description="Fast HTTP probing and technology detection using httpx",
    endpoint="/api/tools/httpx"
)
def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False, status_code: bool = False, content_length: bool = False, title: bool = False, web_server: bool = False, threads: int = 50, additional_args: Optional[str] = None) -> Dict[str, Any]:
    # Kali packages ProjectDiscovery's recon tool as "httpx-toolkit" since
    # "httpx" on PATH there is python3-httpx's unrelated HTTP-client CLI.
    cmd = [resolve_binary("httpx", ["httpx-toolkit", "httpx"]), "-u", target, "-t", str(threads)]
    if probe:
        cmd.append("-probe")
    if tech_detect:
        cmd.append("-tech-detect")
    if status_code:
        cmd.append("-sc")
    if content_length:
        cmd.append("-cl")
    if title:
        cmd.append("-title")
    if web_server:
        cmd.append("-server")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="jaeles_scan",
    category="web",
    description="Advanced vulnerability scanning with custom signatures using Jaeles - for bespoke/private signature sets beyond nuclei_scan's public templates",
    endpoint="/api/tools/jaeles"
)
def jaeles_scan(url: str, signatures: Optional[str] = None, config: Optional[str] = None, threads: int = 20, timeout: int = 20, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["jaeles", "scan", "-u", url, "-c", str(threads), "--timeout", str(timeout)]
    if signatures:
        cmd.extend(["-s", signatures])
    if config:
        cmd.extend(["--config", config])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="katana_crawl",
    category="web",
    description="Next-generation web crawling and spidering using Katana",
    endpoint="/api/tools/katana"
)
def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True, form_extraction: bool = True, output_format: str = "json", timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["katana", "-u", url, "-d", str(depth)]
    if js_crawl:
        cmd.append("-jc")
    if form_extraction:
        cmd.append("-fx")
    if output_format == "json":
        cmd.append("-jsonl")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="nikto_scan",
    category="web",
    description="Web server vulnerability scanning using Nikto - broad but noisy checks for outdated software/server misconfigurations",
    endpoint="/api/tools/nikto"
)
def nikto_scan(target: str, timeout: int = 300, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["nikto", "-h", target]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="nuclei_scan",
    category="web",
    description="Vulnerability scanning using Nuclei templates - fast, community-maintained CVE/misconfig templates; good default first pass",
    endpoint="/api/tools/nuclei"
)
def nuclei_scan(
    target: str,
    severity: Annotated[Optional[str], Field(description="Comma-separated severity filter: 'info', 'low', 'medium', 'high', 'critical'")] = None,
    tags: Annotated[Optional[str], Field(description="Comma-separated Nuclei template tags to include, e.g. 'cve,exposure,misconfig'")] = None,
    template: Annotated[Optional[str], Field(description="Path to a specific Nuclei template or template directory to run, instead of the default set")] = None,
    timeout: int = 300,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["nuclei", "-u", target]
    if severity:
        cmd.extend(["-severity", severity])
    if tags:
        cmd.extend(["-tags", tags])
    if template:
        cmd.extend(["-t", template])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, timeout=timeout)

@ToolRegistry.register(
    name="paramspider_mine",
    category="web",
    description="Parameter mining from web archives using ParamSpider",
    endpoint="/api/tools/paramspider"
)
def paramspider_mine(domain: str, level: int = 2, exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", output: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["paramspider", "-d", domain, "-l", str(level)]
    if exclude:
        cmd.extend(["--exclude", exclude])
    if output:
        cmd.extend(["-o", output])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="wafw00f_scan",
    category="web",
    description="WAF fingerprinting using wafw00f",
    endpoint="/api/tools/wafw00f"
)
def wafw00f_scan(target: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wafw00f", target]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="waybackurls_discover",
    category="web",
    description="Historical URL discovery using Waybackurls",
    endpoint="/api/tools/waybackurls"
)
def waybackurls_discover(domain: str, get_versions: bool = False, no_subs: bool = False, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["waybackurls", domain]
    if get_versions:
        cmd.append("--get-versions")
    if no_subs:
        cmd.append("--no-subs")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="wfuzz_scan",
    category="web",
    description="Web application fuzzing using Wfuzz",
    endpoint="/api/tools/wfuzz"
)
def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wfuzz", "-w", wordlist, url]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="wpscan_scan",
    category="web",
    description="WordPress vulnerability scanning using WPScan",
    endpoint="/api/tools/wpscan"
)
def wpscan_scan(url: str, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["wpscan", "--url", url]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="x8_scan",
    category="web",
    description="Hidden parameter discovery using x8",
    endpoint="/api/tools/x8"
)
def x8_scan(url: str, wordlist: str = "/usr/share/wordlists/x8/params.txt", method: str = "GET", body: Optional[str] = None, headers: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["x8", "-u", url, "-w", wordlist, "-X", method]
    if body:
        cmd.extend(["-b", body])
    if headers:
        cmd.extend(["-H", headers])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="xsser_scan",
    category="web",
    description="XSS vulnerability testing using XSSer - broad payload/WAF-bypass fuzzing engine; use when Dalfox misses a case or WAF evasion is needed",
    endpoint="/api/tools/xsser"
)
def xsser_scan(url: str, params: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["xsser", "--url", url]
    if params:
        cmd.append(f"--param={params}")
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="zap_scan",
    category="web",
    description="Web application scanning using OWASP ZAP - full active+passive proxy-based scan, most thorough but slowest option here",
    endpoint="/api/tools/zap"
)
def zap_scan(
    target: Optional[str] = None,
    scan_type: Annotated[str, Field(description="Not currently read by this handler - every call runs ZAP's -quickurl scan regardless of this value")] = "baseline",
    api_key: Optional[str] = None,
    daemon: bool = False,
    port: str = "8090",
    host: str = "0.0.0.0",
    format: str = "xml",
    output_file: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    if daemon:
        cmd = ["zaproxy", "-daemon", "-host", host, "-port", port]
        if api_key:
            cmd.extend(["-config", f"api.key={api_key}"])
    else:
        cmd = ["zaproxy", "-cmd", "-quickurl", target]
        if output_file:
            cmd.extend(["-quickout", output_file])
        elif format:
            cmd.extend(["-quickout", f"zap_scan_report.{format}"])
        if api_key:
            cmd.extend(["-config", f"api.key={api_key}"])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd)

@ToolRegistry.register(
    name="anew_process",
    category="web",
    description="Append new lines to a file, filtering duplicates, using anew",
    endpoint="/api/tools/anew"
)
def anew_process(input_data: str, output_file: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["anew"]
    if output_file:
        cmd.append(output_file)
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input=input_data)

@ToolRegistry.register(
    name="qsreplace_process",
    category="web",
    description="Query string parameter replacement using qsreplace",
    endpoint="/api/tools/qsreplace"
)
def qsreplace_process(
    urls: str,
    replacement: Annotated[str, Field(description="Value that replaces every query-string parameter value, e.g. 'FUZZ' as a fuzzing placeholder for another tool to substitute")] = "FUZZ",
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    cmd = ["qsreplace", replacement]
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input=urls)

@ToolRegistry.register(
    name="uro_filter",
    category="web",
    description="Filter out semantically similar URLs using uro",
    endpoint="/api/tools/uro"
)
def uro_filter(urls: str, whitelist: Optional[str] = None, blacklist: Optional[str] = None, additional_args: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["uro"]
    if whitelist:
        cmd.extend(["--whitelist", whitelist])
    if blacklist:
        cmd.extend(["--blacklist", blacklist])
    if additional_args:
        cmd.extend(additional_args.split())
    return run_tool_command(cmd, stdin_input=urls)

@ToolRegistry.register(
    name="jwt_analyzer_scan",
    category="web",
    description="JWT token analysis and vulnerability testing",
    endpoint="/api/tools/jwt_analyzer"
)
def jwt_analyzer_scan(jwt_token: str, target_url: Optional[str] = None) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "token": jwt_token[:50] + "..." if len(jwt_token) > 50 else jwt_token,
        "vulnerabilities": [],
        "token_info": {},
        "attack_vectors": []
    }

    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            try:
                header = json.loads(base64.b64decode(header_b64))
                payload = json.loads(base64.b64decode(payload_b64))
                results["token_info"] = {
                    "header": header,
                    "payload": payload,
                    "algorithm": header.get("alg", "unknown")
                }
                algorithm = header.get("alg", "").lower()
                if algorithm == "none":
                    results["vulnerabilities"].append({
                        "type": "none_algorithm",
                        "severity": "CRITICAL",
                        "description": "JWT uses 'none' algorithm - no signature verification"
                    })
                if algorithm in ["hs256", "hs384", "hs512"]:
                    results["attack_vectors"].append("hmac_key_confusion")
                    results["vulnerabilities"].append({
                        "type": "hmac_algorithm",
                        "severity": "MEDIUM",
                        "description": "HMAC algorithm detected - vulnerable to key confusion attacks"
                    })
                exp = payload.get("exp")
                if not exp:
                    results["vulnerabilities"].append({
                        "type": "no_expiration",
                        "severity": "HIGH",
                        "description": "JWT token has no expiration time"
                    })
            except Exception as decode_error:
                results["vulnerabilities"].append({
                    "type": "malformed_token",
                    "severity": "HIGH",
                    "description": f"Token decoding failed: {str(decode_error)}"
                })
    except Exception:
        results["vulnerabilities"].append({
            "type": "invalid_format",
            "severity": "HIGH",
            "description": "Invalid JWT token format"
        })

    if target_url:
        none_token_parts = jwt_token.split('.')
        if len(none_token_parts) >= 2:
            none_header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
            none_token = f"{none_header}.{none_token_parts[1]}."
            try:
                response = requests.get(target_url, headers={"Authorization": f"Bearer {none_token}"}, timeout=30)
                body_text = response.text
            except requests.RequestException:
                body_text = ""
            if "200" in body_text or "success" in body_text.lower():
                results["vulnerabilities"].append({
                    "type": "none_algorithm_accepted",
                    "severity": "CRITICAL",
                    "description": "Server accepts tokens with 'none' algorithm"
                })

    return {"success": True, "jwt_analysis_results": results}

@ToolRegistry.register(
    name="api_schema_analyzer_scan",
    category="web",
    description="API schema analysis for security issues (OpenAPI/Swagger)",
    endpoint="/api/tools/api_schema_analyzer"
)
def api_schema_analyzer_scan(
    schema_url: str,
    schema_type: Annotated[str, Field(description="Schema format: 'openapi'/'swagger' get full endpoint/method extraction; other values skip that parsing")] = "openapi",
) -> Dict[str, Any]:
    try:
        response = requests.get(schema_url, timeout=30)
        schema_content = response.text
        fetch_ok = response.ok
    except requests.RequestException:
        schema_content = ""
        fetch_ok = False

    if not fetch_ok:
        return {"success": False, "error": "Failed to fetch API schema"}

    analysis_results: Dict[str, Any] = {
        "schema_url": schema_url,
        "schema_type": schema_type,
        "endpoints_found": [],
        "security_issues": [],
        "recommendations": []
    }

    try:
        schema_data = json.loads(schema_content)

        if schema_type.lower() in ["openapi", "swagger"]:
            paths = schema_data.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if isinstance(details, dict):
                        endpoint_info = {
                            "path": path,
                            "method": method.upper(),
                            "summary": details.get("summary", ""),
                            "parameters": details.get("parameters", []),
                            "security": details.get("security", [])
                        }
                        analysis_results["endpoints_found"].append(endpoint_info)

                        if not endpoint_info["security"]:
                            analysis_results["security_issues"].append({
                                "endpoint": f"{method.upper()} {path}",
                                "issue": "no_authentication",
                                "severity": "MEDIUM",
                                "description": "Endpoint has no authentication requirements"
                            })

                        for param in endpoint_info["parameters"]:
                            param_name = param.get("name", "").lower()
                            if any(sensitive in param_name for sensitive in ["password", "token", "key", "secret"]):
                                analysis_results["security_issues"].append({
                                    "endpoint": f"{method.upper()} {path}",
                                    "issue": "sensitive_parameter",
                                    "severity": "HIGH",
                                    "description": f"Sensitive parameter detected: {param_name}"
                                })

        if analysis_results["security_issues"]:
            analysis_results["recommendations"] = [
                "Implement authentication for all endpoints",
                "Use HTTPS for all API communications",
                "Validate and sanitize all input parameters",
                "Implement rate limiting",
                "Add proper error handling",
                "Use secure headers (CORS, CSP, etc.)"
            ]

    except json.JSONDecodeError:
        analysis_results["security_issues"].append({
            "endpoint": "schema",
            "issue": "invalid_json",
            "severity": "HIGH",
            "description": "Schema is not valid JSON"
        })

    return {"success": True, "schema_analysis_results": analysis_results}

@ToolRegistry.register(
    name="graphql_scanner_scan",
    category="web",
    description="GraphQL security scanning and introspection testing",
    endpoint="/api/tools/graphql_scanner"
)
def graphql_scanner_scan(endpoint: str, introspection: bool = True, query_depth: int = 10, test_mutations: bool = True) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "endpoint": endpoint,
        "tests_performed": [],
        "vulnerabilities": [],
        "recommendations": []
    }

    if introspection:
        introspection_query = '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            '''
        clean_query = introspection_query.replace('\n', ' ').replace('  ', ' ').strip()
        try:
            response = requests.post(endpoint, json={"query": clean_query}, timeout=30)
            body_text = response.text
        except requests.RequestException:
            body_text = ""

        results["tests_performed"].append("introspection_query")
        if "data" in body_text:
            results["vulnerabilities"].append({
                "type": "introspection_enabled",
                "severity": "MEDIUM",
                "description": "GraphQL introspection is enabled"
            })

    deep_query = "{ " * query_depth + "field" + " }" * query_depth
    try:
        response = requests.post(endpoint, json={"query": deep_query}, timeout=30)
        body_text = response.text
    except requests.RequestException:
        body_text = ""

    results["tests_performed"].append("query_depth_analysis")
    if "error" not in body_text.lower():
        results["vulnerabilities"].append({
            "type": "no_query_depth_limit",
            "severity": "HIGH",
            "description": f"No query depth limiting detected (tested depth: {query_depth})"
        })

    batch_query = [{"query": "{field}"} for _ in range(10)]
    try:
        response = requests.post(endpoint, json=batch_query, timeout=30)
        body_text = response.text
        batch_ok = response.ok
    except requests.RequestException:
        body_text = ""
        batch_ok = False

    results["tests_performed"].append("batch_query_testing")
    if "data" in body_text and batch_ok:
        results["vulnerabilities"].append({
            "type": "batch_queries_allowed",
            "severity": "MEDIUM",
            "description": "Batch queries are allowed without rate limiting"
        })

    if results["vulnerabilities"]:
        results["recommendations"] = [
            "Disable introspection in production",
            "Implement query depth limiting",
            "Add rate limiting for batch queries",
            "Implement query complexity analysis",
            "Add authentication for sensitive operations"
        ]

    return {"success": True, "graphql_scan_results": results}

@ToolRegistry.register(
    name="api_fuzzer_scan",
    category="web",
    description="API endpoint fuzzing with intelligent parameter discovery",
    endpoint="/api/tools/api_fuzzer"
)
def api_fuzzer_scan(base_url: str, endpoints: Optional[List[str]] = None, methods: Optional[List[str]] = None, wordlist: str = "/usr/share/wordlists/api/api-endpoints.txt") -> Dict[str, Any]:
    if methods is None:
        methods = ["GET", "POST", "PUT", "DELETE"]

    if endpoints:
        results = []
        for endpoint in endpoints:
            for method in methods:
                test_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
                try:
                    response = requests.request(method, test_url, timeout=10)
                    result = {"success": True, "status_code": response.status_code, "size": len(response.content)}
                except requests.RequestException as exc:
                    result = {"success": False, "error": str(exc)}
                results.append({"endpoint": endpoint, "method": method, "result": result})
        return {"success": True, "fuzzing_type": "endpoint_testing", "results": results}

    cmd = ["ffuf", "-u", f"{base_url}/FUZZ", "-w", wordlist, "-mc", "200,201,202,204,301,302,307,401,403,405", "-t", "50"]
    result = run_tool_command(cmd)
    return {"success": True, "fuzzing_type": "endpoint_discovery", "result": result}
