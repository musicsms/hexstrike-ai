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
