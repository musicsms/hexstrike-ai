from hexstrike.core.recovery import ErrorType, classify_error
from hexstrike.core.registry import ToolSpec


def test_classify_error_timeout():
    assert classify_error("Connection timeout after 30s") == ErrorType.TIMEOUT
    assert classify_error("operation timed out") == ErrorType.TIMEOUT


def test_classify_error_permission_denied():
    assert classify_error("Permission denied") == ErrorType.PERMISSION_DENIED
    assert classify_error("sudo required to run this scan") == ErrorType.PERMISSION_DENIED


def test_classify_error_network_unreachable():
    assert classify_error("Network unreachable") == ErrorType.NETWORK_UNREACHABLE
    assert classify_error("Connection refused") == ErrorType.NETWORK_UNREACHABLE


def test_classify_error_rate_limited():
    assert classify_error("429 Too Many Requests") == ErrorType.RATE_LIMITED
    assert classify_error("quota exceeded") == ErrorType.RATE_LIMITED


def test_classify_error_tool_not_found():
    assert classify_error("bash: nmap: command not found") == ErrorType.TOOL_NOT_FOUND
    assert classify_error("executable not found") == ErrorType.TOOL_NOT_FOUND


def test_classify_error_invalid_parameters():
    assert classify_error("nmap: invalid option -- 'z'") == ErrorType.INVALID_PARAMETERS
    assert classify_error("syntax error near unexpected token") == ErrorType.INVALID_PARAMETERS


def test_classify_error_resource_exhausted():
    assert classify_error("out of memory") == ErrorType.RESOURCE_EXHAUSTED
    assert classify_error("too many open files") == ErrorType.RESOURCE_EXHAUSTED


def test_classify_error_authentication_failed():
    assert classify_error("authentication failed") == ErrorType.AUTHENTICATION_FAILED
    assert classify_error("expired token") == ErrorType.AUTHENTICATION_FAILED


def test_classify_error_target_unreachable():
    assert classify_error("target not responding") == ErrorType.TARGET_UNREACHABLE
    assert classify_error("dns resolution failed") == ErrorType.TARGET_UNREACHABLE


def test_classify_error_parsing_error():
    assert classify_error("json decode error") == ErrorType.PARSING_ERROR
    assert classify_error("malformed response") == ErrorType.PARSING_ERROR


def test_classify_error_unknown_fallback():
    assert classify_error("") == ErrorType.UNKNOWN
    assert classify_error("something completely unrecognizable happened") == ErrorType.UNKNOWN


def test_classify_error_exception_type_shortcuts():
    assert classify_error("", TimeoutError()) == ErrorType.TIMEOUT
    assert classify_error("", PermissionError()) == ErrorType.PERMISSION_DENIED
    assert classify_error("", ConnectionError()) == ErrorType.NETWORK_UNREACHABLE
    assert classify_error("", FileNotFoundError()) == ErrorType.TOOL_NOT_FOUND


from hexstrike.core.recovery import RecoveryAction, RECOVERY_STRATEGIES, select_best_strategy


def test_recovery_strategies_cover_every_error_type():
    assert set(RECOVERY_STRATEGIES.keys()) == set(ErrorType)


def test_select_best_strategy_timeout_progression():
    strategies = RECOVERY_STRATEGIES[ErrorType.TIMEOUT]
    assert select_best_strategy(strategies, 1).action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE
    assert select_best_strategy(strategies, 2).action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE
    assert select_best_strategy(strategies, 3).action == RecoveryAction.RETRY_WITH_BACKOFF


def test_select_best_strategy_permission_denied_escalates_immediately():
    strategies = RECOVERY_STRATEGIES[ErrorType.PERMISSION_DENIED]
    assert select_best_strategy(strategies, 1).action == RecoveryAction.ESCALATE_TO_HUMAN


def test_select_best_strategy_falls_back_to_escalation_when_all_exhausted():
    strategies = RECOVERY_STRATEGIES[ErrorType.TIMEOUT]
    # attempt_count 4 exceeds every strategy's max_attempts (3, 2, 1)
    result = select_best_strategy(strategies, 4)
    assert result.action == RecoveryAction.ESCALATE_TO_HUMAN
    assert result.max_attempts == 1


import hexstrike.core.recovery as recovery_module
from hexstrike.core.recovery import get_alternative_tool


def test_get_alternative_tool_returns_none_when_no_alternatives_listed(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {})
    assert get_alternative_tool("totally_unknown_tool", {}) is None


def test_get_alternative_tool_filters_to_registered_tools_only(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {"tool_a": ["tool_b", "tool_c", "tool_d"]})
    monkeypatch.setattr(
        recovery_module.ToolRegistry, "get",
        staticmethod(lambda name: object() if name in ("tool_c", "tool_d") else None),
    )
    # tool_b isn't "registered" per the stub above, so it's skipped entirely
    assert get_alternative_tool("tool_a", {}) == "tool_c"


def test_get_alternative_tool_context_filter_falls_back_when_all_excluded(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {"tool_a": ["nmap_scan", "masscan_scan"]})
    monkeypatch.setattr(recovery_module.ToolRegistry, "get", staticmethod(lambda name: object()))
    # Both candidates are in the require_no_privileges denylist, so the filter
    # excludes everything and (matching legacy behavior) falls back to the
    # unfiltered candidate list rather than returning None.
    assert get_alternative_tool("tool_a", {"require_no_privileges": True}) == "nmap_scan"


def test_get_alternative_tool_context_filter_excludes_when_alternative_remains(monkeypatch):
    monkeypatch.setattr(recovery_module, "TOOL_ALTERNATIVES", {"tool_a": ["nmap_scan", "rustscan_scan"]})
    monkeypatch.setattr(recovery_module.ToolRegistry, "get", staticmethod(lambda name: object()))
    assert get_alternative_tool("tool_a", {"require_no_privileges": True}) == "rustscan_scan"


def test_tool_alternatives_nmap_scan_entry_uses_current_registry_names():
    assert "rustscan_scan" in recovery_module.TOOL_ALTERNATIVES["nmap_scan"]


from hexstrike.core.recovery import adjust_params


def _fake_spec(name, handler):
    return ToolSpec(name=name, category="test", description="", endpoint="/x", handler=handler)


def test_adjust_params_applies_tool_specific_override():
    def handler(target, threads=10, additional_args=None):
        return {"success": True}
    spec = _fake_spec("gobuster_dir", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "threads": 10})
    assert result["threads"] == 10  # gobuster_dir's TIMEOUT override sets threads to 10


def test_adjust_params_skips_keys_not_in_handler_signature():
    def handler(target, additional_args=None):  # no "threads" param
        return {"success": True}
    spec = _fake_spec("gobuster_dir", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x"})
    assert "threads" not in result


def test_adjust_params_extra_flags_appends_to_existing_additional_args():
    def handler(target, additional_args=None):
        return {"success": True}
    spec = _fake_spec("nmap_scan", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "additional_args": "-Pn"})
    assert result["additional_args"] == "-Pn -T2"


def test_adjust_params_extra_flags_sets_when_absent():
    def handler(target, additional_args=None):
        return {"success": True}
    spec = _fake_spec("nmap_scan", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x"})
    assert result["additional_args"] == "-T2"


def test_adjust_params_falls_back_to_generic_for_unlisted_tool():
    def handler(target, threads=10, additional_args=None):
        return {"success": True}
    spec = _fake_spec("some_future_tool", handler)

    result = adjust_params(spec, ErrorType.RATE_LIMITED, {"target": "x", "threads": 10})
    assert result["threads"] == 3  # GENERIC_ADJUSTMENTS[RATE_LIMITED]


def test_adjust_params_generic_timeout_doubles_current_value():
    def handler(target, timeout=300, additional_args=None):
        return {"success": True}
    spec = _fake_spec("some_future_tool", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "timeout": 100})
    assert result["timeout"] == 200


def test_adjust_params_does_not_mutate_input_dict():
    def handler(target, threads=10, additional_args=None):
        return {"success": True}
    spec = _fake_spec("gobuster_dir", handler)

    original = {"target": "x", "threads": 99}
    adjust_params(spec, ErrorType.TIMEOUT, original)
    assert original["threads"] == 99


from hexstrike.core.recovery import build_escalation


def test_build_escalation_shape():
    escalation = build_escalation("nmap_scan", "10.0.0.1", ErrorType.PERMISSION_DENIED, "permission denied", 2, "high")
    assert escalation["tool"] == "nmap_scan"
    assert escalation["target"] == "10.0.0.1"
    assert escalation["error_type"] == "permission_denied"
    assert escalation["error_message"] == "permission denied"
    assert escalation["attempt_count"] == 2
    assert escalation["urgency"] == "high"
    assert escalation["suggested_actions"] == [
        "Run the command with sudo privileges",
        "Check file/directory permissions",
        "Verify user is in required groups",
    ]


def test_build_escalation_tool_not_found_suggestion_names_the_tool():
    escalation = build_escalation("katana_crawl", "x.com", ErrorType.TOOL_NOT_FOUND, "not found", 1, "low")
    assert escalation["suggested_actions"][0] == "Install katana_crawl using package manager"


def test_build_escalation_default_suggestion_for_unmapped_error_type():
    escalation = build_escalation("nmap_scan", "x", ErrorType.PARSING_ERROR, "malformed", 1)
    assert escalation["urgency"] == "medium"  # default param
    assert escalation["suggested_actions"] == ["Review error details and logs"]


from hexstrike.core.recovery import execute_with_recovery


def test_execute_with_recovery_backoff_then_succeeds(monkeypatch):
    sleeps = []
    monkeypatch.setattr(recovery_module.time, "sleep", lambda seconds: sleeps.append(seconds))

    calls = {"count": 0}

    def handler(target):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"success": False, "error": "rate limit exceeded"}
        return {"success": True, "output": "ok"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})

    assert result["success"] is True
    assert calls["count"] == 2
    assert result["recovery_info"]["attempts_made"] == 2
    assert result["recovery_info"]["recovery_applied"] is True
    assert len(result["recovery_info"]["recovery_history"]) == 1
    assert result["recovery_info"]["recovery_history"][0]["recovery_action"] == "retry_with_backoff"
    assert sleeps == [30]  # RATE_LIMITED initial_delay, attempt 1: 30 * 1.5**0


def test_execute_with_recovery_adjusts_params_then_succeeds():
    seen_timeouts = []

    def handler(target, timeout=300):
        seen_timeouts.append(timeout)
        if len(seen_timeouts) == 1:
            return {"success": False, "error": "operation timed out"}
        return {"success": True, "output": "ok"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x", "timeout": 300})

    assert result["success"] is True
    assert seen_timeouts == [300, 600]  # GENERIC_ADJUSTMENTS[TIMEOUT] doubles it
    assert result["recovery_info"]["attempts_made"] == 2
    assert result["recovery_info"]["recovery_history"][0]["recovery_action"] == "retry_with_reduced_scope"


def test_execute_with_recovery_escalates_and_stops_after_one_attempt():
    calls = {"count": 0}

    def handler(target):
        calls["count"] += 1
        return {"success": False, "error": "permission denied"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})

    assert result["success"] is False
    assert calls["count"] == 1
    assert result["recovery_info"]["attempts_made"] == 1
    assert result["human_escalation"]["tool"] == "some_tool"
    assert result["human_escalation"]["target"] == "x"
    assert result["human_escalation"]["error_type"] == "permission_denied"


def test_execute_with_recovery_handles_raised_exception():
    def handler(target):
        raise FileNotFoundError("nmap: command not found")

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})

    # TOOL_NOT_FOUND's best strategy at attempt 1 is SWITCH_TO_ALTERNATIVE_TOOL;
    # no alternative is registered for "some_tool" so it just stops.
    assert result["success"] is False
    assert result["recovery_info"]["attempts_made"] == 1


def test_adjust_params_generic_timeout_not_forced_when_caller_did_not_set_it():
    def handler(target, timeout=20, additional_args=None):
        return {"success": True}
    spec = _fake_spec("some_future_tool", handler)

    # Caller never passed "timeout" — must NOT be forced to 600 even though
    # the handler accepts a timeout param with its own, different default.
    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x"})
    assert "timeout" not in result


def test_adjust_params_generic_timeout_caps_growth():
    def handler(target, timeout=300, additional_args=None):
        return {"success": True}
    spec = _fake_spec("some_future_tool", handler)

    result = adjust_params(spec, ErrorType.TIMEOUT, {"target": "x", "timeout": 1000})
    assert result["timeout"] == 1800  # min(1000*2, 1800), not 2000


def test_execute_with_recovery_no_sleep_on_terminal_attempt(monkeypatch):
    sleeps = []
    monkeypatch.setattr(recovery_module.time, "sleep", lambda seconds: sleeps.append(seconds))

    def handler(target):
        return {"success": False, "error": "rate limit exceeded"}

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"})  # default max_attempts=3

    assert result["success"] is False
    assert result["recovery_info"]["attempts_made"] == 3
    # RATE_LIMITED picks RETRY_WITH_BACKOFF at attempts 1 and 2 (sleeps),
    # then again at attempt 3 (RETRY_WITH_BACKOFF is the only strategy still
    # viable — ADJUST_PARAMETERS's max_attempts=2 excludes it) but must NOT
    # sleep since attempt 3 == max_attempts.
    assert sleeps == [30, 45]


def test_execute_with_recovery_uses_exception_type_shortcut_for_bare_exception():
    def handler(target):
        raise TimeoutError()  # empty message — classify_error("") alone would be UNKNOWN

    spec = _fake_spec("some_tool", handler)
    result = execute_with_recovery(spec, {"target": "x"}, max_attempts=1)

    # TIMEOUT's attempt-1 winner is RETRY_WITH_REDUCED_SCOPE (see
    # test_select_best_strategy_timeout_progression). UNKNOWN's attempt-1
    # winner is ESCALATE_TO_HUMAN. Getting retry_with_reduced_scope here
    # proves the exception object — not just its (empty) string — drove
    # classification to TIMEOUT.
    assert result["recovery_info"]["recovery_history"][0]["recovery_action"] == "retry_with_reduced_scope"


def test_execute_with_recovery_suggests_real_registered_alternative():
    real_spec = recovery_module.ToolRegistry.get("nmap_scan")
    assert real_spec is not None

    def handler(**kwargs):
        return {"success": False, "error": "nmap: command not found"}

    spec = ToolSpec(name="nmap_scan", category=real_spec.category, description="", endpoint=real_spec.endpoint, handler=handler)
    result = execute_with_recovery(spec, {"target": "10.0.0.1"})

    assert result["success"] is False
    assert result["alternative_tool_suggested"] == "rustscan_scan"


def test_determine_operation_type_known_and_unknown():
    assert recovery_module._determine_operation_type("nmap_scan") == "network_discovery"
    assert recovery_module._determine_operation_type("gobuster_dir") == "web_discovery"
    assert recovery_module._determine_operation_type("nuclei_scan") == "vulnerability_scanning"
    assert recovery_module._determine_operation_type("amass_enum") == "subdomain_enumeration"
    assert recovery_module._determine_operation_type("totally_unknown_tool") == "unknown_operation"


def test_basic_port_check_returns_ports_with_successful_connect(monkeypatch):
    class FakeSocket:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            return 0 if addr[1] in (22, 80) else 1

        def close(self):
            pass

    monkeypatch.setattr(recovery_module.socket, "socket", lambda *a, **k: FakeSocket())
    assert recovery_module._basic_port_check("10.0.0.5") == [22, 80]


def test_basic_port_check_empty_target_returns_empty_list():
    assert recovery_module._basic_port_check("") == []


def test_basic_directory_check_returns_dirs_with_matching_status(monkeypatch):
    class FakeResponse:
        def __init__(self, status_code):
            self.status_code = status_code

    def fake_head(url, timeout=None, allow_redirects=None):
        if url.endswith("/admin") or url.endswith("/robots.txt"):
            return FakeResponse(200)
        return FakeResponse(404)

    monkeypatch.setattr(recovery_module.requests, "head", fake_head)
    assert recovery_module._basic_directory_check("http://example.com") == ["/admin", "/robots.txt"]


def test_basic_directory_check_empty_target_returns_empty_list():
    assert recovery_module._basic_directory_check("") == []


def test_basic_security_check_flags_missing_headers(monkeypatch):
    class FakeResponse:
        headers = {"Content-Security-Policy": "default-src 'self'"}

    monkeypatch.setattr(recovery_module.requests, "get", lambda url, timeout=None: FakeResponse())
    vulns = recovery_module._basic_security_check("http://example.com")
    headers_flagged = {v["header"] for v in vulns}
    assert headers_flagged == {
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
    }


def test_basic_security_check_empty_target_returns_empty_list():
    assert recovery_module._basic_security_check("") == []


def test_basic_security_check_connection_error_reported(monkeypatch):
    def raise_error(url, timeout=None):
        raise Exception("refused")

    monkeypatch.setattr(recovery_module.requests, "get", raise_error)
    vulns = recovery_module._basic_security_check("http://example.com")
    assert len(vulns) == 1
    assert vulns[0]["type"] == "connection_error"


def test_get_manual_recommendations_includes_base_and_component_specific():
    recs = recovery_module._get_manual_recommendations("network_discovery", ["nmap_scan"])
    assert "Manually test common ports using telnet or nc" in recs
    assert "Consider using online port scanners" in recs


def test_get_manual_recommendations_unknown_operation_returns_empty_base():
    recs = recovery_module._get_manual_recommendations("unknown_operation", [])
    assert recs == []


def test_apply_graceful_degradation_network_discovery(monkeypatch):
    monkeypatch.setattr(recovery_module, "_basic_port_check", lambda target: [80, 443])
    result = recovery_module.apply_graceful_degradation(
        "nmap_scan", "10.0.0.5", {"success": False, "error": "target not responding"}
    )
    assert result["success"] is False
    assert result["open_ports"] == [80, 443]
    assert result["degradation_info"]["operation"] == "network_discovery"
    assert result["degradation_info"]["partial_success"] is True
    assert result["degradation_info"]["fallback_applied"] is True
    assert "manual_recommendations" in result


def test_apply_graceful_degradation_web_discovery(monkeypatch):
    monkeypatch.setattr(recovery_module, "_basic_directory_check", lambda target: ["/admin"])
    result = recovery_module.apply_graceful_degradation(
        "gobuster_dir", "http://x.com", {"success": False, "error": "connection refused"}
    )
    assert result["directories"] == ["/admin"]
    assert result["degradation_info"]["operation"] == "web_discovery"


def test_apply_graceful_degradation_vulnerability_scanning(monkeypatch):
    monkeypatch.setattr(recovery_module, "_basic_security_check", lambda target: [{"type": "missing_security_header"}])
    result = recovery_module.apply_graceful_degradation(
        "nuclei_scan", "http://x.com", {"success": False, "error": "timeout"}
    )
    assert result["vulnerabilities"] == [{"type": "missing_security_header"}]
    assert result["degradation_info"]["operation"] == "vulnerability_scanning"


def test_apply_graceful_degradation_unknown_operation_adds_no_extra_field():
    result = recovery_module.apply_graceful_degradation(
        "totally_unknown_tool", "x", {"success": False, "error": "x"}
    )
    assert "open_ports" not in result
    assert "directories" not in result
    assert "vulnerabilities" not in result
    assert result["degradation_info"]["operation"] == "unknown_operation"


def test_apply_graceful_degradation_does_not_mutate_input_dict():
    original = {"success": False, "error": "x"}
    recovery_module.apply_graceful_degradation("totally_unknown_tool", "x", original)
    assert "degradation_info" not in original


def test_execute_with_recovery_applies_graceful_degradation_for_target_unreachable(monkeypatch):
    monkeypatch.setattr(recovery_module, "_basic_port_check", lambda target: [22, 80])

    def handler(target):
        return {"success": False, "error": "target not responding"}

    spec = _fake_spec("nmap_scan", handler)
    result = execute_with_recovery(spec, {"target": "10.0.0.5"})

    assert result["success"] is False
    assert result["degradation_info"]["operation"] == "network_discovery"
    assert result["degradation_info"]["fallback_applied"] is True
    assert result["open_ports"] == [22, 80]
    assert "manual_recommendations" in result
    assert result["recovery_info"]["attempts_made"] == 1
