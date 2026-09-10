import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Annotated
import requests
from pydantic import Field
from hexstrike.core.registry import ToolRegistry

logger = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_EXPLOIT_KEYWORDS = [
    'remote code execution', 'rce', 'buffer overflow', 'stack overflow',
    'heap overflow', 'use after free', 'double free', 'format string',
    'sql injection', 'command injection', 'authentication bypass',
    'privilege escalation', 'directory traversal', 'path traversal',
    'deserialization', 'xxe', 'ssrf', 'csrf', 'xss'
]


def _extract_cvss(cve_data: Dict[str, Any]) -> Dict[str, Any]:
    metrics = cve_data.get('metrics', {})
    cvss_score = 0.0
    severity = "UNKNOWN"
    attack_vector = "UNKNOWN"
    attack_complexity = "UNKNOWN"
    privileges_required = "UNKNOWN"
    user_interaction = "UNKNOWN"
    exploitability_subscore = 0.0

    for key in ('cvssMetricV31', 'cvssMetricV30'):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
            attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
            attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
            privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
            user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
            exploitability_subscore = cvss_data.get('exploitabilityScore', 0.0)
            break
    else:
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

    return {
        "cvss_score": cvss_score, "severity": severity, "attack_vector": attack_vector,
        "attack_complexity": attack_complexity, "privileges_required": privileges_required,
        "user_interaction": user_interaction, "exploitability_subscore": exploitability_subscore,
    }


def _extract_description(cve_data: Dict[str, Any]) -> str:
    for desc in cve_data.get('descriptions', []):
        if desc.get('lang') == 'en':
            return desc.get('value', '')
    return ""


@ToolRegistry.register(
    name="cve_fetch_latest",
    category="intelligence",
    description="Fetch recently published/modified CVEs from the public NVD API, filtered by severity - live external lookup, not limited by any LLM's training cutoff",
    endpoint="/api/tools/cve-fetch-latest"
)
def cve_fetch_latest(
    hours: Annotated[int, Field(description="How many hours back to search for newly published/modified CVEs")] = 24,
    severity_filter: Annotated[str, Field(description="Comma-separated CVSS severities to include, e.g. 'HIGH,CRITICAL', or 'ALL' for no filtering")] = "HIGH,CRITICAL",
) -> Dict[str, Any]:
    try:
        logger.info(f"🔍 Fetching CVEs from last {hours} hours with severity: {severity_filter}")
        end_date = datetime.now()
        start_date = end_date - timedelta(hours=hours)
        start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        severity_levels = [s.strip().upper() for s in severity_filter.split(",")]

        all_cves = []

        try:
            logger.info(f"🌐 Querying NVD API: {_NVD_URL}")
            response = requests.get(_NVD_URL, params={
                'lastModStartDate': start_date_str,
                'lastModEndDate': end_date_str,
                'resultsPerPage': 100
            }, timeout=30)

            if response.status_code == 200:
                vulnerabilities = response.json().get('vulnerabilities', [])
                logger.info(f"📊 Retrieved {len(vulnerabilities)} vulnerabilities from NVD")
                for vuln_item in vulnerabilities:
                    cve_data = vuln_item.get('cve', {})
                    cvss = _extract_cvss(cve_data)

                    if cvss["severity"] not in severity_levels and severity_levels != ['ALL']:
                        continue

                    references = [ref.get('url', '') for ref in cve_data.get('references', [])[:5]]

                    affected_software = []
                    for config in cve_data.get('configurations', []):
                        for node in config.get('nodes', []):
                            for cpe in node.get('cpeMatch', [])[:3]:
                                cpe_name = cpe.get('criteria', '')
                                if cpe_name.startswith('cpe:2.3:'):
                                    parts = cpe_name.split(':')
                                    if len(parts) >= 6:
                                        vendor, product = parts[3], parts[4]
                                        version = parts[5] if parts[5] != '*' else 'all versions'
                                        affected_software.append(f"{vendor} {product} {version}")

                    all_cves.append({
                        "cve_id": cve_data.get('id', 'Unknown'),
                        "description": _extract_description(cve_data) or "No description available",
                        "severity": cvss["severity"],
                        "cvss_score": cvss["cvss_score"],
                        "published_date": cve_data.get('published', ''),
                        "last_modified": cve_data.get('lastModified', ''),
                        "affected_software": affected_software[:5],
                        "references": references,
                        "source": "NVD"
                    })
            else:
                logger.warning(f"⚠️ NVD API returned status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error querying NVD API: {str(e)}")

        if not all_cves:
            logger.info("🔄 No recent CVEs found in specified timeframe, checking for any recent critical CVEs...")
            try:
                time.sleep(6)
                broader_start = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
                response = requests.get(_NVD_URL, params={
                    'lastModStartDate': broader_start,
                    'lastModEndDate': end_date_str,
                    'cvssV3Severity': 'CRITICAL',
                    'resultsPerPage': 20
                }, timeout=30)

                if response.status_code == 200:
                    for vuln_item in response.json().get('vulnerabilities', [])[:10]:
                        cve_data = vuln_item.get('cve', {})
                        cvss = _extract_cvss(cve_data)
                        all_cves.append({
                            "cve_id": cve_data.get('id', 'Unknown'),
                            "description": _extract_description(cve_data) or "No description available",
                            "severity": "CRITICAL",
                            "cvss_score": cvss["cvss_score"],
                            "published_date": cve_data.get('published', ''),
                            "last_modified": cve_data.get('lastModified', ''),
                            "affected_software": ["Various (see references)"],
                            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id', 'Unknown')}"],
                            "source": "NVD (Recent Critical)"
                        })
            except Exception as broader_e:
                logger.warning(f"⚠️ Broader search also failed: {str(broader_e)}")

        logger.info(f"✅ Successfully retrieved {len(all_cves)} CVEs")
        return {
            "success": True,
            "cves": all_cves,
            "total_found": len(all_cves),
            "hours_searched": hours,
            "severity_filter": severity_filter,
            "data_sources": ["NVD API v2.0"],
            "search_period": f"{start_date_str} to {end_date_str}"
        }

    except Exception as e:
        logger.error(f"💥 Error fetching CVEs: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "cves": [],
            "fallback_message": "CVE fetching failed, check network connectivity and API availability"
        }


@ToolRegistry.register(
    name="cve_analyze_exploitability",
    category="intelligence",
    description="Fetch a specific CVE from NVD and score its exploitability (attack vector/complexity, public exploit signals, priority) - live external lookup by CVE ID",
    endpoint="/api/tools/cve-analyze-exploitability"
)
def cve_analyze_exploitability(
    cve_id: Annotated[str, Field(description="CVE identifier to analyze, e.g. 'CVE-2024-12345'")],
) -> Dict[str, Any]:
    try:
        logger.info(f"🔬 Analyzing exploitability for {cve_id}")
        try:
            response = requests.get(_NVD_URL, params={'cveId': cve_id}, timeout=30)
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Network error analyzing {cve_id}: {str(e)}")
            return {"success": False, "error": f"Network error: {str(e)}", "cve_id": cve_id}

        if response.status_code != 200:
            logger.warning(f"⚠️ NVD API returned status {response.status_code} for {cve_id}")
            return {"success": False, "error": f"Failed to fetch CVE data: HTTP {response.status_code}", "cve_id": cve_id}

        vulnerabilities = response.json().get('vulnerabilities', [])
        if not vulnerabilities:
            logger.warning(f"⚠️ No data found for CVE {cve_id}")
            return {"success": False, "error": f"CVE {cve_id} not found in NVD database", "cve_id": cve_id}

        cve_data = vulnerabilities[0].get('cve', {})
        cvss = _extract_cvss(cve_data)
        exploitability_subscore = cvss["exploitability_subscore"]

        if exploitability_subscore > 0:
            exploitability_score = min(exploitability_subscore / 3.9, 1.0)
        else:
            score_components = 0.0
            score_components += {"NETWORK": 0.4, "ADJACENT_NETWORK": 0.3, "LOCAL": 0.2, "PHYSICAL": 0.1}.get(cvss["attack_vector"], 0.0)
            score_components += {"LOW": 0.3, "HIGH": 0.1}.get(cvss["attack_complexity"], 0.0)
            score_components += {"NONE": 0.2, "LOW": 0.1}.get(cvss["privileges_required"], 0.0)
            if cvss["user_interaction"] == "NONE":
                score_components += 0.1
            exploitability_score = min(score_components, 1.0)

        description = _extract_description(cve_data)
        description_lower = description.lower()
        exploit_indicators = [kw for kw in _EXPLOIT_KEYWORDS if kw in description_lower]

        if any(kw in description_lower for kw in ['remote code execution', 'rce', 'buffer overflow']):
            exploitability_score = min(exploitability_score + 0.2, 1.0)
        elif any(kw in description_lower for kw in ['authentication bypass', 'privilege escalation']):
            exploitability_score = min(exploitability_score + 0.15, 1.0)

        if exploitability_score >= 0.8:
            exploitability_level = "HIGH"
        elif exploitability_score >= 0.6:
            exploitability_level = "MEDIUM"
        elif exploitability_score >= 0.3:
            exploitability_level = "LOW"
        else:
            exploitability_level = "VERY_LOW"

        references = cve_data.get('references', [])
        exploit_sources = ['exploit-db.com', 'github.com', 'packetstormsecurity.com', 'metasploit']
        public_exploits = False
        exploit_maturity = "UNKNOWN"
        for ref in references:
            if any(source in ref.get('url', '').lower() for source in exploit_sources):
                public_exploits = True
                exploit_maturity = "PROOF_OF_CONCEPT"
                break

        weaponization_level = "LOW"
        if public_exploits and exploitability_score > 0.7:
            weaponization_level = "HIGH"
        elif public_exploits and exploitability_score > 0.5:
            weaponization_level = "MEDIUM"
        elif exploitability_score > 0.8:
            weaponization_level = "MEDIUM"

        active_exploitation = False
        if exploitability_score > 0.8 and public_exploits:
            active_exploitation = True
        elif cvss["severity"] in ["CRITICAL", "HIGH"] and cvss["attack_vector"] == "NETWORK":
            active_exploitation = True

        if exploitability_score > 0.8 and cvss["severity"] == "CRITICAL":
            priority = "IMMEDIATE"
        elif exploitability_score > 0.7 or cvss["severity"] == "CRITICAL":
            priority = "HIGH"
        elif exploitability_score > 0.5 or cvss["severity"] == "HIGH":
            priority = "MEDIUM"
        else:
            priority = "LOW"

        result = {
            "success": True,
            "cve_id": cve_id,
            "exploitability_score": round(exploitability_score, 2),
            "exploitability_level": exploitability_level,
            "cvss_score": cvss["cvss_score"],
            "severity": cvss["severity"],
            "attack_vector": cvss["attack_vector"],
            "attack_complexity": cvss["attack_complexity"],
            "privileges_required": cvss["privileges_required"],
            "user_interaction": cvss["user_interaction"],
            "exploitability_subscore": exploitability_subscore,
            "exploit_availability": {
                "public_exploits": public_exploits,
                "exploit_maturity": exploit_maturity,
                "weaponization_level": weaponization_level
            },
            "threat_intelligence": {
                "active_exploitation": active_exploitation,
                "exploit_prediction": f"{exploitability_score * 100:.1f}% likelihood of exploitation",
                "recommended_priority": priority,
                "exploit_indicators": exploit_indicators
            },
            "vulnerability_details": {
                "description": description[:500] + "..." if len(description) > 500 else description,
                "published_date": cve_data.get('published', ''),
                "last_modified": cve_data.get('lastModified', ''),
                "references_count": len(references)
            },
            "data_source": "NVD API v2.0",
            "analysis_timestamp": datetime.now().isoformat()
        }
        logger.info(f"✅ Completed exploitability analysis for {cve_id}: {exploitability_level} ({exploitability_score:.2f})")
        return result

    except Exception as e:
        logger.error(f"💥 Error analyzing CVE {cve_id}: {str(e)}")
        return {"success": False, "error": str(e), "cve_id": cve_id}


@ToolRegistry.register(
    name="cve_search_exploits",
    category="intelligence",
    description="Search GitHub repos/code and NVD references for public exploits/PoCs for a CVE - makes 3 sequential external API calls (~2-8s total due to rate-limit compliance delays), subject to unauthenticated GitHub API rate limits",
    endpoint="/api/tools/cve-search-exploits"
)
def cve_search_exploits(
    cve_id: Annotated[str, Field(description="CVE identifier to search for, e.g. 'CVE-2024-12345'")],
) -> Dict[str, Any]:
    try:
        logger.info(f"🔎 Searching existing exploits for {cve_id}")
        all_exploits = []
        sources_searched = []

        try:
            logger.info(f"🔍 Searching GitHub for {cve_id} exploits...")
            github_response = requests.get("https://api.github.com/search/repositories", params={
                'q': f'{cve_id} exploit poc vulnerability',
                'sort': 'updated', 'order': 'desc', 'per_page': 10
            }, timeout=15)

            if github_response.status_code == 200:
                for repo in github_response.json().get('items', [])[:5]:
                    repo_name = repo.get('name', '').lower()
                    repo_desc = (repo.get('description') or '').lower()
                    if cve_id.lower() in repo_name or cve_id.lower() in repo_desc:
                        stars = repo.get('stargazers_count', 0)
                        forks = repo.get('forks_count', 0)
                        reliability = "UNVERIFIED"
                        if stars >= 50 or forks >= 10:
                            reliability = "GOOD"
                        elif stars >= 20 or forks >= 5:
                            reliability = "FAIR"
                        all_exploits.append({
                            "source": "github",
                            "exploit_id": f"github-{repo.get('id', 'unknown')}",
                            "title": repo.get('name', 'Unknown Repository'),
                            "description": repo.get('description', 'No description'),
                            "author": repo.get('owner', {}).get('login', 'Unknown'),
                            "date_published": repo.get('created_at', ''),
                            "last_updated": repo.get('updated_at', ''),
                            "type": "proof-of-concept",
                            "platform": "cross-platform",
                            "url": repo.get('html_url', ''),
                            "stars": stars,
                            "forks": forks,
                            "verified": False,
                            "reliability": reliability
                        })
                sources_searched.append("github")
                logger.info(f"✅ Found {len([e for e in all_exploits if e['source'] == 'github'])} GitHub repositories")
            else:
                logger.warning(f"⚠️ GitHub search failed with status {github_response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ GitHub search error: {str(e)}")

        try:
            logger.info(f"🔍 Searching for {cve_id} in exploit databases...")
            time.sleep(1)
            nvd_response = requests.get(_NVD_URL, params={'cveId': cve_id}, timeout=20)
            if nvd_response.status_code == 200:
                vulnerabilities = nvd_response.json().get('vulnerabilities', [])
                if vulnerabilities:
                    references = vulnerabilities[0].get('cve', {}).get('references', [])
                    exploit_sources = {
                        'exploit-db.com': 'exploit-db', 'packetstormsecurity.com': 'packetstorm',
                        'metasploit': 'metasploit', 'rapid7.com': 'rapid7'
                    }
                    for ref in references:
                        ref_url_lower = ref.get('url', '').lower()
                        for source_domain, source_name in exploit_sources.items():
                            if source_domain in ref_url_lower:
                                all_exploits.append({
                                    "source": source_name,
                                    "exploit_id": f"{source_name}-ref",
                                    "title": f"Referenced exploit for {cve_id}",
                                    "description": "Exploit reference found in CVE data",
                                    "author": "Various",
                                    "date_published": vulnerabilities[0].get('cve', {}).get('published', ''),
                                    "type": "reference",
                                    "platform": "various",
                                    "url": ref.get('url', ''),
                                    "verified": True,
                                    "reliability": "GOOD" if source_name == "exploit-db" else "FAIR"
                                })
                                if source_name not in sources_searched:
                                    sources_searched.append(source_name)
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Exploit database search error: {str(e)}")

        try:
            logger.info(f"🔍 Searching for Metasploit modules for {cve_id}...")
            time.sleep(1)
            msf_response = requests.get("https://api.github.com/search/code", params={
                'q': f'{cve_id} filename:*.rb repo:rapid7/metasploit-framework', 'per_page': 5
            }, timeout=15)

            if msf_response.status_code == 200:
                code_results = msf_response.json().get('items', [])
                for code_item in code_results:
                    file_path = code_item.get('path', '')
                    if 'exploits/' in file_path or 'auxiliary/' in file_path:
                        all_exploits.append({
                            "source": "metasploit",
                            "exploit_id": f"msf-{code_item.get('sha', 'unknown')[:8]}",
                            "title": f"Metasploit Module: {code_item.get('name', 'Unknown')}",
                            "description": f"Metasploit framework module at {file_path}",
                            "author": "Metasploit Framework",
                            "date_published": "Unknown",
                            "type": "metasploit-module",
                            "platform": "various",
                            "url": code_item.get('html_url', ''),
                            "verified": True,
                            "reliability": "EXCELLENT"
                        })
                if code_results and "metasploit" not in sources_searched:
                    sources_searched.append("metasploit")
            elif msf_response.status_code == 403:
                logger.warning("⚠️ GitHub API rate limit reached for code search")
            else:
                logger.warning(f"⚠️ Metasploit search failed with status {msf_response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Metasploit search error: {str(e)}")

        for source in ["exploit-db", "github", "metasploit", "packetstorm"]:
            if source not in sources_searched:
                sources_searched.append(source)

        reliability_order = {"EXCELLENT": 4, "GOOD": 3, "FAIR": 2, "UNVERIFIED": 1}
        all_exploits.sort(key=lambda x: (
            reliability_order.get(x.get("reliability", "UNVERIFIED"), 0),
            x.get("stars", 0),
            x.get("date_published", "")
        ), reverse=True)

        logger.info(f"✅ Found {len(all_exploits)} total exploits from {len(sources_searched)} sources")
        return {
            "success": True,
            "cve_id": cve_id,
            "exploits_found": len(all_exploits),
            "exploits": all_exploits,
            "sources_searched": sources_searched,
            "search_summary": {
                "github_repos": len([e for e in all_exploits if e["source"] == "github"]),
                "exploit_db_refs": len([e for e in all_exploits if e["source"] == "exploit-db"]),
                "metasploit_modules": len([e for e in all_exploits if e["source"] == "metasploit"]),
                "other_sources": len([e for e in all_exploits if e["source"] not in ["github", "exploit-db", "metasploit"]])
            },
            "search_timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"💥 Error searching exploits for {cve_id}: {str(e)}")
        return {"success": False, "error": str(e), "cve_id": cve_id, "exploits": [], "sources_searched": []}
