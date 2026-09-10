import pytest
from hexstrike.core.registry import ToolRegistry
import hexstrike.tools
import hexstrike.tools.cve as cve_module


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr(cve_module.time, "sleep", lambda *_args, **_kwargs: None)


class FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def json(self):
        return self._json_data


def _nvd_vuln(cve_id="CVE-2024-0001", severity="HIGH", score=7.5, description="A vulnerability",
              references=None, configurations=None):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "exploitabilityScore": 3.9,
                    }
                }]
            },
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "references": references or [],
            "configurations": configurations or [],
        }
    }


def test_intelligence_category_has_6_tools():
    # intelligence.py contributes the 3 detector tools; cve.py contributes these 3.
    names = {t.name for t in ToolRegistry.get_by_category("intelligence")}
    assert names == {
        "technology_detect", "rate_limit_detect", "rate_limit_adjust_timing",
        "cve_fetch_latest", "cve_analyze_exploitability", "cve_search_exploits",
    }


def test_cve_fetch_latest_filters_by_severity(monkeypatch):
    tool = ToolRegistry.get("cve_fetch_latest")
    assert tool is not None
    assert tool.category == "intelligence"
    assert tool.endpoint == "/api/tools/cve-fetch-latest"

    matching = _nvd_vuln(cve_id="CVE-2024-0001", severity="HIGH")
    non_matching = _nvd_vuln(cve_id="CVE-2024-0002", severity="LOW")

    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(200, {
        "vulnerabilities": [matching, non_matching]
    }))

    res = tool.handler(hours=24, severity_filter="HIGH,CRITICAL")
    assert res["success"] is True
    assert res["total_found"] == 1
    assert res["cves"][0]["cve_id"] == "CVE-2024-0001"


def test_cve_fetch_latest_all_severity_includes_everything(monkeypatch):
    tool = ToolRegistry.get("cve_fetch_latest")
    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(200, {
        "vulnerabilities": [_nvd_vuln(severity="HIGH"), _nvd_vuln(cve_id="CVE-2024-0002", severity="LOW")]
    }))

    res = tool.handler(severity_filter="ALL")
    assert res["total_found"] == 2


def test_cve_fetch_latest_extracts_affected_software(monkeypatch):
    tool = ToolRegistry.get("cve_fetch_latest")
    configs = [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:http_server:2.4.1"}]}]}]
    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(200, {
        "vulnerabilities": [_nvd_vuln(configurations=configs)]
    }))

    res = tool.handler(severity_filter="ALL")
    assert res["cves"][0]["affected_software"] == ["apache http_server 2.4.1"]


def test_cve_fetch_latest_falls_back_when_no_results(monkeypatch):
    tool = ToolRegistry.get("cve_fetch_latest")
    calls = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(200, {"vulnerabilities": []})
        return FakeResponse(200, {"vulnerabilities": [_nvd_vuln(cve_id="CVE-2024-9999", severity="CRITICAL")]})

    monkeypatch.setattr(cve_module.requests, "get", fake_get)
    res = tool.handler()
    assert res["success"] is True
    assert res["total_found"] == 1
    assert res["cves"][0]["source"] == "NVD (Recent Critical)"
    assert calls["n"] == 2


def test_cve_fetch_latest_request_exception_falls_back(monkeypatch):
    tool = ToolRegistry.get("cve_fetch_latest")

    def fake_get(url, params=None, timeout=None):
        if 'cvssV3Severity' in (params or {}):
            return FakeResponse(200, {"vulnerabilities": []})
        raise cve_module.requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(cve_module.requests, "get", fake_get)
    res = tool.handler()
    assert res["success"] is True
    assert res["cves"] == []


def test_cve_fetch_latest_unexpected_exception_returns_failure(monkeypatch):
    tool = ToolRegistry.get("cve_fetch_latest")

    def raise_unexpected(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cve_module.requests, "get", raise_unexpected)
    res = tool.handler()
    assert res["success"] is False
    assert res["error"] == "kaboom"
    assert res["cves"] == []


def test_cve_analyze_exploitability_success_with_rce_bonus(monkeypatch):
    tool = ToolRegistry.get("cve_analyze_exploitability")
    assert tool is not None
    assert tool.endpoint == "/api/tools/cve-analyze-exploitability"

    vuln = _nvd_vuln(description="A remote code execution vulnerability")
    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(200, {"vulnerabilities": [vuln]}))

    res = tool.handler(cve_id="CVE-2024-0001")
    assert res["success"] is True
    assert res["cve_id"] == "CVE-2024-0001"
    assert res["exploitability_level"] == "HIGH"
    assert "remote code execution" in res["threat_intelligence"]["exploit_indicators"]


def test_cve_analyze_exploitability_non_200(monkeypatch):
    tool = ToolRegistry.get("cve_analyze_exploitability")
    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(503))
    res = tool.handler(cve_id="CVE-2024-0001")
    assert res["success"] is False
    assert "HTTP 503" in res["error"]


def test_cve_analyze_exploitability_not_found(monkeypatch):
    tool = ToolRegistry.get("cve_analyze_exploitability")
    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(200, {"vulnerabilities": []}))
    res = tool.handler(cve_id="CVE-2024-9999")
    assert res["success"] is False
    assert "not found" in res["error"]


def test_cve_analyze_exploitability_network_error(monkeypatch):
    tool = ToolRegistry.get("cve_analyze_exploitability")

    def raise_conn_error(*a, **k):
        raise cve_module.requests.exceptions.ConnectionError("no route")

    monkeypatch.setattr(cve_module.requests, "get", raise_conn_error)
    res = tool.handler(cve_id="CVE-2024-0001")
    assert res["success"] is False
    assert "Network error" in res["error"]


def test_cve_analyze_exploitability_public_exploit_detected(monkeypatch):
    tool = ToolRegistry.get("cve_analyze_exploitability")
    vuln = _nvd_vuln(references=[{"url": "https://www.exploit-db.com/exploits/12345"}])
    monkeypatch.setattr(cve_module.requests, "get", lambda *a, **k: FakeResponse(200, {"vulnerabilities": [vuln]}))

    res = tool.handler(cve_id="CVE-2024-0001")
    assert res["exploit_availability"]["public_exploits"] is True
    assert res["exploit_availability"]["exploit_maturity"] == "PROOF_OF_CONCEPT"


def test_cve_search_exploits_aggregates_all_sources(monkeypatch):
    tool = ToolRegistry.get("cve_search_exploits")
    assert tool is not None
    assert tool.endpoint == "/api/tools/cve-search-exploits"

    def fake_get(url, params=None, timeout=None):
        if "search/repositories" in url:
            return FakeResponse(200, {"items": [{
                "id": 1, "name": "CVE-2024-0001-poc", "description": "poc for cve-2024-0001",
                "owner": {"login": "researcher"}, "created_at": "2024-01-01", "updated_at": "2024-01-02",
                "html_url": "https://github.com/researcher/CVE-2024-0001-poc",
                "stargazers_count": 100, "forks_count": 20
            }]})
        if "search/code" in url:
            return FakeResponse(200, {"items": [{
                "path": "modules/exploits/linux/http/foo.rb", "name": "foo.rb", "sha": "abcdef1234",
                "html_url": "https://github.com/rapid7/metasploit-framework/blob/master/foo.rb"
            }]})
        return FakeResponse(200, {"vulnerabilities": [_nvd_vuln(
            references=[{"url": "https://www.exploit-db.com/exploits/99999"}]
        )]})

    monkeypatch.setattr(cve_module.requests, "get", fake_get)
    res = tool.handler(cve_id="CVE-2024-0001")

    assert res["success"] is True
    assert res["exploits_found"] == 3
    assert res["search_summary"]["github_repos"] == 1
    assert res["search_summary"]["exploit_db_refs"] == 1
    assert res["search_summary"]["metasploit_modules"] == 1
    assert res["exploits"][0]["reliability"] == "EXCELLENT"


def test_cve_search_exploits_github_failure_still_returns_other_sources(monkeypatch):
    tool = ToolRegistry.get("cve_search_exploits")

    def fake_get(url, params=None, timeout=None):
        if "search/repositories" in url:
            raise cve_module.requests.exceptions.ConnectionError("rate limited")
        if "search/code" in url:
            return FakeResponse(403)
        return FakeResponse(200, {"vulnerabilities": []})

    monkeypatch.setattr(cve_module.requests, "get", fake_get)
    res = tool.handler(cve_id="CVE-2024-0001")

    assert res["success"] is True
    assert res["exploits_found"] == 0
    assert set(res["sources_searched"]) == {"exploit-db", "github", "metasploit", "packetstorm"}


def test_cve_search_exploits_unexpected_exception_returns_failure(monkeypatch):
    tool = ToolRegistry.get("cve_search_exploits")

    def raise_unexpected(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(cve_module.requests, "get", raise_unexpected)
    res = tool.handler(cve_id="CVE-2024-0001")
    assert res["success"] is False
    assert res["exploits"] == []
