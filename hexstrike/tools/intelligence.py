import re
from typing import Dict, Any, List, Optional, Annotated
from pydantic import Field
from hexstrike.core.registry import ToolRegistry

_DETECTION_PATTERNS = {
    "web_servers": {
        "apache": ["Apache", "apache", "httpd"],
        "nginx": ["nginx", "Nginx"],
        "iis": ["Microsoft-IIS", "IIS"],
        "tomcat": ["Tomcat", "Apache-Coyote"],
        "jetty": ["Jetty"],
        "lighttpd": ["lighttpd"]
    },
    "frameworks": {
        "django": ["Django", "django", "csrftoken"],
        "flask": ["Flask", "Werkzeug"],
        "express": ["Express", "X-Powered-By: Express"],
        "laravel": ["Laravel", "laravel_session"],
        "symfony": ["Symfony", "symfony"],
        "rails": ["Ruby on Rails", "rails", "_session_id"],
        "spring": ["Spring", "JSESSIONID"],
        "struts": ["Struts", "struts"]
    },
    "cms": {
        "wordpress": ["wp-content", "wp-includes", "WordPress", "/wp-admin/"],
        "drupal": ["Drupal", "drupal", "/sites/default/", "X-Drupal-Cache"],
        "joomla": ["Joomla", "joomla", "/administrator/", "com_content"],
        "magento": ["Magento", "magento", "Mage.Cookies"],
        "prestashop": ["PrestaShop", "prestashop"],
        "opencart": ["OpenCart", "opencart"]
    },
    "databases": {
        "mysql": ["MySQL", "mysql", "phpMyAdmin"],
        "postgresql": ["PostgreSQL", "postgres"],
        "mssql": ["Microsoft SQL Server", "MSSQL"],
        "oracle": ["Oracle", "oracle"],
        "mongodb": ["MongoDB", "mongo"],
        "redis": ["Redis", "redis"]
    },
    "languages": {
        "php": ["PHP", "php", ".php", "X-Powered-By: PHP"],
        "python": ["Python", "python", ".py"],
        "java": ["Java", "java", ".jsp", ".do"],
        "dotnet": ["ASP.NET", ".aspx", ".asp", "X-AspNet-Version"],
        "nodejs": ["Node.js", "node", ".js"],
        "ruby": ["Ruby", "ruby", ".rb"],
        "go": ["Go", "golang"],
        "rust": ["Rust", "rust"]
    },
    "security": {
        "waf": ["cloudflare", "CloudFlare", "X-CF-Ray", "incapsula", "Incapsula", "sucuri", "Sucuri"],
        "load_balancer": ["F5", "BigIP", "HAProxy", "nginx", "AWS-ALB"],
        "cdn": ["CloudFront", "Fastly", "KeyCDN", "MaxCDN", "Cloudflare"]
    }
}

_PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 993: "imaps", 995: "pop3s",
    1433: "mssql", 3306: "mysql", 5432: "postgresql", 6379: "redis",
    27017: "mongodb", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached"
}

_RATE_LIMIT_INDICATORS = [
    "rate limit", "too many requests", "429", "throttle", "slow down",
    "retry after", "quota exceeded", "api limit", "request limit"
]

_TIMING_PROFILES = {
    "aggressive": {"delay": 0.1, "threads": 50, "timeout": 5},
    "normal": {"delay": 0.5, "threads": 20, "timeout": 10},
    "conservative": {"delay": 1.0, "threads": 10, "timeout": 15},
    "stealth": {"delay": 2.0, "threads": 5, "timeout": 30}
}


@ToolRegistry.register(
    name="technology_detect",
    category="intelligence",
    description="Fingerprint web server/framework/CMS/database/language/security stack from HTTP headers, page content, and open ports - pure pattern matching, makes no network requests itself",
    endpoint="/api/tools/technology-detect"
)
def technology_detect(
    headers: Annotated[Optional[Dict[str, str]], Field(description="HTTP response headers to scan for technology fingerprints, e.g. {'Server': 'nginx', 'X-Powered-By': 'PHP/8.1'}")] = None,
    content: Annotated[str, Field(description="Page body/HTML to scan for technology fingerprints")] = "",
    ports: Annotated[Optional[List[int]], Field(description="Open ports to map to known services, e.g. [22, 80, 3306]")] = None,
) -> Dict[str, Any]:
    detected: Dict[str, List[str]] = {
        "web_servers": [], "frameworks": [], "cms": [],
        "databases": [], "languages": [], "security": [], "services": []
    }

    if headers:
        for category, tech_patterns in _DETECTION_PATTERNS.items():
            for tech, patterns in tech_patterns.items():
                for header_name, header_value in headers.items():
                    for pattern in patterns:
                        if pattern.lower() in header_value.lower() or pattern.lower() in header_name.lower():
                            if tech not in detected[category]:
                                detected[category].append(tech)

    if content:
        content_lower = content.lower()
        for category, tech_patterns in _DETECTION_PATTERNS.items():
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content_lower:
                        if tech not in detected[category]:
                            detected[category].append(tech)

    if ports:
        for port in ports:
            if port in _PORT_SERVICES:
                service = _PORT_SERVICES[port]
                if service not in detected["services"]:
                    detected["services"].append(service)

    return {"success": True, "detected": detected}


def _recommend_timing_profile(confidence: float) -> str:
    if confidence >= 0.8:
        return "stealth"
    elif confidence >= 0.5:
        return "conservative"
    elif confidence >= 0.2:
        return "normal"
    else:
        return "aggressive"


@ToolRegistry.register(
    name="rate_limit_detect",
    category="intelligence",
    description="Detect rate limiting from a tool/HTTP response (status code, body text, headers) and recommend a timing profile - pair with rate_limit_adjust_timing to apply it",
    endpoint="/api/tools/rate-limit-detect"
)
def rate_limit_detect(
    response_text: Annotated[str, Field(description="Response body text to scan for rate-limit indicator phrases, e.g. 'too many requests'")],
    status_code: Annotated[int, Field(description="HTTP status code of the response; 429 is treated as a strong signal")],
    headers: Annotated[Optional[Dict[str, str]], Field(description="Response headers to check for rate-limit headers, e.g. 'X-RateLimit-*', 'Retry-After'")] = None,
) -> Dict[str, Any]:
    rate_limit_detected = False
    confidence = 0.0
    indicators_found = []

    if status_code == 429:
        rate_limit_detected = True
        confidence += 0.8
        indicators_found.append("HTTP 429 status")

    response_lower = response_text.lower()
    for indicator in _RATE_LIMIT_INDICATORS:
        if indicator in response_lower:
            rate_limit_detected = True
            confidence += 0.2
            indicators_found.append(f"Text: '{indicator}'")

    if headers:
        rate_limit_headers = ["x-ratelimit", "retry-after", "x-rate-limit"]
        for header_name in headers.keys():
            for rl_header in rate_limit_headers:
                if rl_header.lower() in header_name.lower():
                    rate_limit_detected = True
                    confidence += 0.3
                    indicators_found.append(f"Header: {header_name}")

    confidence = min(1.0, confidence)

    return {
        "success": True,
        "detected": rate_limit_detected,
        "confidence": confidence,
        "indicators": indicators_found,
        "recommended_profile": _recommend_timing_profile(confidence)
    }


@ToolRegistry.register(
    name="rate_limit_adjust_timing",
    category="intelligence",
    description="Apply a timing profile (from rate_limit_detect's recommendation) to a tool's parameter dict, rewriting threads/delay/timeout and any -t/--threads/--delay flags in additional_args",
    endpoint="/api/tools/rate-limit-adjust-timing"
)
def rate_limit_adjust_timing(
    current_params: Annotated[Dict[str, Any], Field(description="Tool parameter dict to adjust in place, e.g. {'threads': 50, 'additional_args': '-t 50'}")],
    profile: Annotated[str, Field(description="Timing profile to apply: 'aggressive', 'normal', 'conservative', or 'stealth' (see rate_limit_detect's recommended_profile)")],
) -> Dict[str, Any]:
    timing = _TIMING_PROFILES.get(profile, _TIMING_PROFILES["normal"])
    adjusted_params = current_params.copy()

    if "threads" in adjusted_params:
        adjusted_params["threads"] = timing["threads"]
    if "delay" in adjusted_params:
        adjusted_params["delay"] = timing["delay"]
    if "timeout" in adjusted_params:
        adjusted_params["timeout"] = timing["timeout"]

    if "additional_args" in adjusted_params:
        args = adjusted_params["additional_args"]
        args = re.sub(r'-t\s+\d+', '', args)
        args = re.sub(r'--threads\s+\d+', '', args)
        args = re.sub(r'--delay\s+[\d.]+', '', args)
        args += f" -t {timing['threads']}"
        if timing["delay"] > 0:
            args += f" --delay {timing['delay']}"
        adjusted_params["additional_args"] = args.strip()

    return {"success": True, "profile": profile, "adjusted_params": adjusted_params}
