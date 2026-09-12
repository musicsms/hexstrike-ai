import re
import time
import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from hexstrike.core.registry import ToolRegistry, ToolSpec


class ErrorType(Enum):
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"


_ERROR_PATTERNS: Dict[str, ErrorType] = {
    r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
    r"operation timed out|command timeout": ErrorType.TIMEOUT,

    r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
    r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,

    r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
    r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,

    r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
    r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,

    r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
    r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,

    r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
    r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,

    r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
    r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,

    r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
    r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,

    r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
    r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,

    r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
    r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR,
}


def classify_error(error_message: str, exception: Optional[Exception] = None) -> ErrorType:
    if exception is not None:
        if isinstance(exception, TimeoutError):
            return ErrorType.TIMEOUT
        if isinstance(exception, PermissionError):
            return ErrorType.PERMISSION_DENIED
        if isinstance(exception, ConnectionError):
            return ErrorType.NETWORK_UNREACHABLE
        if isinstance(exception, FileNotFoundError):
            return ErrorType.TOOL_NOT_FOUND

    text = (error_message or "").lower()
    for pattern, error_type in _ERROR_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            return error_type
    return ErrorType.UNKNOWN


class RecoveryAction(Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"


@dataclass
class RecoveryStrategy:
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds, used only for strategy scoring


RECOVERY_STRATEGIES: Dict[ErrorType, List[RecoveryStrategy]] = {
    ErrorType.TIMEOUT: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 5, "max_delay": 60}, 3, 2.0, 0.7, 30),
        RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, {"reduce_threads": True, "reduce_timeout": True}, 2, 1.0, 0.8, 45),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"prefer_faster_tools": True}, 1, 1.0, 0.6, 60),
    ],
    ErrorType.PERMISSION_DENIED: [
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Privilege escalation required", "urgency": "medium"}, 1, 1.0, 0.9, 300),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"require_no_privileges": True}, 1, 1.0, 0.5, 30),
    ],
    ErrorType.NETWORK_UNREACHABLE: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 10, "max_delay": 120}, 3, 2.0, 0.6, 60),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"prefer_offline_tools": True}, 1, 1.0, 0.4, 30),
    ],
    ErrorType.RATE_LIMITED: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 30, "max_delay": 300}, 5, 1.5, 0.9, 180),
        RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"reduce_rate": True, "increase_delays": True}, 2, 1.0, 0.8, 120),
    ],
    ErrorType.TOOL_NOT_FOUND: [
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"find_equivalent": True}, 1, 1.0, 0.7, 15),
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Tool installation required", "urgency": "low"}, 1, 1.0, 0.9, 600),
    ],
    ErrorType.INVALID_PARAMETERS: [
        RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"use_defaults": True, "remove_invalid": True}, 3, 1.0, 0.8, 10),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"simpler_interface": True}, 1, 1.0, 0.6, 30),
    ],
    ErrorType.RESOURCE_EXHAUSTED: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, {"reduce_memory": True, "reduce_threads": True}, 2, 1.0, 0.7, 60),
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 60, "max_delay": 300}, 2, 2.0, 0.5, 180),
    ],
    ErrorType.AUTHENTICATION_FAILED: [
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Authentication credentials required", "urgency": "high"}, 1, 1.0, 0.9, 300),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"no_auth_required": True}, 1, 1.0, 0.4, 30),
    ],
    ErrorType.TARGET_UNREACHABLE: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 15, "max_delay": 180}, 3, 2.0, 0.6, 90),
        RecoveryStrategy(RecoveryAction.GRACEFUL_DEGRADATION, {"skip_target": True, "continue_with_others": True}, 1, 1.0, 1.0, 5),
    ],
    ErrorType.PARSING_ERROR: [
        RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"change_output_format": True, "add_parsing_flags": True}, 2, 1.0, 0.7, 20),
        RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"better_output_format": True}, 1, 1.0, 0.6, 30),
    ],
    ErrorType.UNKNOWN: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 5, "max_delay": 30}, 2, 2.0, 0.3, 45),
        RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Unknown error encountered", "urgency": "medium"}, 1, 1.0, 0.9, 300),
    ],
}


def select_best_strategy(strategies: List[RecoveryStrategy], attempt_count: int) -> RecoveryStrategy:
    viable = [s for s in strategies if attempt_count <= s.max_attempts]
    if not viable:
        return RecoveryStrategy(
            action=RecoveryAction.ESCALATE_TO_HUMAN,
            parameters={"message": "All recovery strategies exhausted", "urgency": "high"},
            max_attempts=1,
            backoff_multiplier=1.0,
            success_probability=0.9,
            estimated_time=300,
        )

    scored = []
    for strategy in viable:
        adjusted_probability = strategy.success_probability * (0.9 ** (attempt_count - 1))
        score = adjusted_probability - (strategy.estimated_time / 1000.0)
        scored.append((score, strategy))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return scored[0][1]


TOOL_ALTERNATIVES: Dict[str, List[str]] = {
    "nmap_scan": ["rustscan_scan", "masscan_scan", "zmap"],
    "rustscan_scan": ["nmap_scan", "masscan_scan"],
    "masscan_scan": ["nmap_scan", "rustscan_scan", "zmap"],

    "gobuster_dir": ["feroxbuster_scan", "dirsearch_scan", "ffuf_fuzz", "dirb_scan"],
    "feroxbuster_scan": ["gobuster_dir", "dirsearch_scan", "ffuf_fuzz"],
    "dirsearch_scan": ["gobuster_dir", "feroxbuster_scan", "ffuf_fuzz"],
    "ffuf_fuzz": ["gobuster_dir", "feroxbuster_scan", "dirsearch_scan"],

    "nuclei_scan": ["jaeles_scan", "nikto_scan", "w3af"],
    "jaeles_scan": ["nuclei_scan", "nikto_scan"],
    "nikto_scan": ["nuclei_scan", "jaeles_scan", "w3af"],

    "katana_crawl": ["gau_discover", "waybackurls_discover", "hakrawler_crawl"],
    "gau_discover": ["katana_crawl", "waybackurls_discover", "hakrawler_crawl"],
    "waybackurls_discover": ["gau_discover", "katana_crawl", "hakrawler_crawl"],

    "arjun_scan": ["paramspider_mine", "x8_scan", "ffuf_fuzz"],
    "paramspider_mine": ["arjun_scan", "x8_scan"],
    "x8_scan": ["arjun_scan", "paramspider_mine"],

    "sqlmap_scan": ["sqlninja", "jsql-injection"],
    "dalfox_scan": ["xsser_scan", "xsstrike"],

    "subfinder": ["amass_enum", "assetfinder", "findomain"],
    "amass_enum": ["subfinder", "assetfinder", "findomain"],
    "assetfinder": ["subfinder", "amass_enum", "findomain"],

    "prowler_scan": ["scout_suite_scan", "cloudmapper_run"],
    "scout_suite_scan": ["prowler_scan", "cloudmapper_run"],

    "trivy_scan": ["clair_scan", "docker_bench_security_scan"],
    "clair_scan": ["trivy_scan", "docker_bench_security_scan"],

    "ghidra_analyze": ["radare2_analyze", "ida", "binary-ninja"],
    "radare2_analyze": ["ghidra_analyze", "objdump_scan", "gdb_analyze"],
    "gdb_analyze": ["radare2_analyze", "lldb"],

    "pwntools_exploit": ["ropper_scan", "ropgadget"],
    "ropper_scan": ["ropgadget", "pwntools_exploit"],
}


def get_alternative_tool(tool_name: str, strategy_params: Dict[str, Any]) -> Optional[str]:
    candidates = [t for t in TOOL_ALTERNATIVES.get(tool_name, []) if ToolRegistry.get(t) is not None]
    if not candidates:
        return None

    filtered = []
    for alt in candidates:
        if strategy_params.get("require_no_privileges") and alt in ("nmap_scan", "masscan_scan"):
            continue
        if strategy_params.get("prefer_faster_tools") and alt in ("amass_enum", "w3af"):
            continue
        filtered.append(alt)

    if not filtered:
        filtered = candidates
    return filtered[0]


TOOL_PARAM_ADJUSTMENTS: Dict[str, Dict[ErrorType, Dict[str, Any]]] = {
    "nmap_scan": {
        ErrorType.TIMEOUT: {"extra_flags": "-T2"},
        ErrorType.RATE_LIMITED: {"extra_flags": "-T1"},
    },
    "gobuster_dir": {
        ErrorType.TIMEOUT: {"threads": 10},
        ErrorType.RATE_LIMITED: {"threads": 5},
        ErrorType.RESOURCE_EXHAUSTED: {"threads": 5},
    },
    "nuclei_scan": {
        ErrorType.TIMEOUT: {"extra_flags": "-timeout 30"},
        ErrorType.RATE_LIMITED: {"extra_flags": "-rl 10"},
    },
    "feroxbuster_scan": {
        ErrorType.TIMEOUT: {"threads": 5},
        ErrorType.RATE_LIMITED: {"threads": 3},
    },
    "ffuf_fuzz": {
        ErrorType.RATE_LIMITED: {"extra_flags": "-rate 10"},
    },
}

GENERIC_ADJUSTMENTS: Dict[ErrorType, Dict[str, Any]] = {
    ErrorType.TIMEOUT: {"timeout": lambda current: (current or 300) * 2},
    ErrorType.RATE_LIMITED: {"threads": 3},
    ErrorType.RESOURCE_EXHAUSTED: {"threads": 3},
}


def adjust_params(spec: ToolSpec, error_type: ErrorType, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    accepted = set(inspect.signature(spec.handler).parameters)
    adjustments = TOOL_PARAM_ADJUSTMENTS.get(spec.name, {}).get(error_type)
    if adjustments is None:
        adjustments = GENERIC_ADJUSTMENTS.get(error_type, {})

    adjusted = dict(kwargs)
    for key, value in adjustments.items():
        if key == "extra_flags":
            if "additional_args" not in accepted:
                continue
            existing = adjusted.get("additional_args") or ""
            adjusted["additional_args"] = f"{existing} {value}".strip()
            continue
        if key in accepted:
            adjusted[key] = value(adjusted.get(key)) if callable(value) else value
    return adjusted


def _human_suggestions(tool_name: str, error_type: ErrorType) -> List[str]:
    if error_type == ErrorType.PERMISSION_DENIED:
        return [
            "Run the command with sudo privileges",
            "Check file/directory permissions",
            "Verify user is in required groups",
        ]
    if error_type == ErrorType.TOOL_NOT_FOUND:
        return [
            f"Install {tool_name} using package manager",
            "Check if tool is in PATH",
            "Verify tool installation",
        ]
    if error_type == ErrorType.NETWORK_UNREACHABLE:
        return [
            "Check network connectivity",
            "Verify target is accessible",
            "Check firewall rules",
        ]
    if error_type == ErrorType.RATE_LIMITED:
        return [
            "Wait before retrying",
            "Use slower scan rates",
            "Check API rate limits",
        ]
    return ["Review error details and logs"]


def build_escalation(
    tool_name: str,
    target: str,
    error_type: ErrorType,
    error_message: str,
    attempt_count: int,
    urgency: str = "medium",
) -> Dict[str, Any]:
    return {
        "tool": tool_name,
        "target": target,
        "error_type": error_type.value,
        "error_message": error_message,
        "attempt_count": attempt_count,
        "urgency": urgency,
        "suggested_actions": _human_suggestions(tool_name, error_type),
    }


def execute_with_recovery(spec: ToolSpec, kwargs: Dict[str, Any], max_attempts: int = 3) -> Dict[str, Any]:
    current_kwargs = dict(kwargs)
    history: List[Dict[str, Any]] = []
    attempt = 0
    last_result: Dict[str, Any] = {"success": False, "error": "recovery loop did not execute"}

    while attempt < max_attempts:
        attempt += 1
        try:
            result = spec.handler(**current_kwargs)
        except Exception as exc:
            result = {"success": False, "error": str(exc)}
        last_result = result

        if result.get("success"):
            result["recovery_info"] = {
                "attempts_made": attempt,
                "recovery_applied": len(history) > 0,
                "recovery_history": history,
            }
            return result

        error_type = classify_error(result.get("error") or "")
        strategy = select_best_strategy(RECOVERY_STRATEGIES[error_type], attempt)
        history.append({
            "attempt": attempt,
            "error": result.get("error"),
            "recovery_action": strategy.action.value,
        })

        if strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
            delay = min(
                strategy.parameters.get("initial_delay", 5) * (strategy.backoff_multiplier ** (attempt - 1)),
                strategy.parameters.get("max_delay", 60),
            )
            time.sleep(delay)
            continue

        if strategy.action in (RecoveryAction.RETRY_WITH_REDUCED_SCOPE, RecoveryAction.ADJUST_PARAMETERS):
            current_kwargs = adjust_params(spec, error_type, current_kwargs)
            continue

        if strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
            alt = get_alternative_tool(spec.name, strategy.parameters)
            if alt:
                last_result["alternative_tool_suggested"] = alt
            break

        if strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
            last_result["human_escalation"] = build_escalation(
                spec.name,
                current_kwargs.get("target", "unknown"),
                error_type,
                result.get("error"),
                attempt,
                strategy.parameters.get("urgency", "medium"),
            )
            break

        # ABORT_OPERATION, and GRACEFUL_DEGRADATION (stubbed as abort in this
        # port — see spec non-goals): stop, fall through to the return below.
        break

    last_result["recovery_info"] = {
        "attempts_made": attempt,
        "recovery_applied": True,
        "recovery_history": history,
    }
    return last_result
