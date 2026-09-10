from hexstrike.core.registry import ToolRegistry
import hexstrike.tools


def test_intelligence_category_includes_detector_tools():
    # The "intelligence" category is split across intelligence.py (detectors, this file)
    # and cve.py (CVE lookups) - see test_cve_tools.py for the full category count.
    names = {t.name for t in ToolRegistry.get_by_category("intelligence")}
    assert {"technology_detect", "rate_limit_detect", "rate_limit_adjust_timing"} <= names


def test_technology_detect_from_headers():
    tool = ToolRegistry.get("technology_detect")
    assert tool is not None
    assert tool.endpoint == "/api/tools/technology-detect"

    res = tool.handler(headers={"Server": "nginx", "X-Powered-By": "PHP/8.1"})
    assert res["success"] is True
    assert "nginx" in res["detected"]["web_servers"]
    assert "php" in res["detected"]["languages"]


def test_technology_detect_from_content():
    tool = ToolRegistry.get("technology_detect")
    res = tool.handler(content="<html><body>Powered by WordPress, wp-content/themes/x</body></html>")
    assert res["success"] is True
    assert "wordpress" in res["detected"]["cms"]


def test_technology_detect_from_ports():
    tool = ToolRegistry.get("technology_detect")
    res = tool.handler(ports=[22, 3306, 9999])
    assert res["success"] is True
    assert set(res["detected"]["services"]) == {"ssh", "mysql"}


def test_technology_detect_no_input_returns_empty_categories():
    tool = ToolRegistry.get("technology_detect")
    res = tool.handler()
    assert res["success"] is True
    assert all(v == [] for v in res["detected"].values())


def test_rate_limit_detect_status_code_429():
    tool = ToolRegistry.get("rate_limit_detect")
    assert tool is not None
    assert tool.endpoint == "/api/tools/rate-limit-detect"

    res = tool.handler(response_text="", status_code=429)
    assert res["success"] is True
    assert res["detected"] is True
    assert res["confidence"] == 0.8
    assert res["recommended_profile"] == "stealth"


def test_rate_limit_detect_text_and_header_indicators_reach_stealth():
    tool = ToolRegistry.get("rate_limit_detect")
    res = tool.handler(
        response_text="Error: rate limit exceeded, please slow down",
        status_code=429,
        headers={"X-RateLimit-Remaining": "0"},
    )
    assert res["detected"] is True
    assert res["confidence"] == 1.0
    assert res["recommended_profile"] == "stealth"
    assert len(res["indicators"]) >= 3


def test_rate_limit_detect_no_indicators():
    tool = ToolRegistry.get("rate_limit_detect")
    res = tool.handler(response_text="OK", status_code=200)
    assert res["detected"] is False
    assert res["confidence"] == 0.0
    assert res["recommended_profile"] == "aggressive"
    assert res["indicators"] == []


def test_rate_limit_adjust_timing_updates_known_keys():
    tool = ToolRegistry.get("rate_limit_adjust_timing")
    assert tool is not None
    assert tool.endpoint == "/api/tools/rate-limit-adjust-timing"

    res = tool.handler(current_params={"threads": 50, "delay": 0, "timeout": 5}, profile="stealth")
    assert res["success"] is True
    assert res["adjusted_params"] == {"threads": 5, "delay": 2.0, "timeout": 30}


def test_rate_limit_adjust_timing_rewrites_additional_args():
    tool = ToolRegistry.get("rate_limit_adjust_timing")
    res = tool.handler(current_params={"additional_args": "-t 50 --threads 50"}, profile="conservative")
    assert res["adjusted_params"]["additional_args"] == "-t 10 --delay 1.0"


def test_rate_limit_adjust_timing_unknown_profile_falls_back_to_normal():
    tool = ToolRegistry.get("rate_limit_adjust_timing")
    res = tool.handler(current_params={"threads": 1}, profile="does-not-exist")
    assert res["adjusted_params"]["threads"] == 20
