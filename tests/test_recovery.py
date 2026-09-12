import pytest
from hexstrike.core.recovery import ErrorType, classify_error


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
