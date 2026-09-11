import os
import stat
from hexstrike.tools.base import run_tool_command, resolve_binary


def test_resolve_binary_env_override_wins(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_BIN_HTTPX", "custom-httpx")
    assert resolve_binary("httpx", ["httpx-toolkit", "httpx"]) == "custom-httpx"


def test_resolve_binary_picks_first_available_candidate(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_BIN_HTTPX", raising=False)
    monkeypatch.setattr(
        "hexstrike.tools.base.is_tool_available",
        lambda name: name == "httpx",
    )
    assert resolve_binary("httpx", ["httpx-toolkit", "httpx"]) == "httpx"


def test_resolve_binary_falls_back_to_first_candidate_when_none_found(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_BIN_HTTPX", raising=False)
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: False)
    assert resolve_binary("httpx", ["httpx-toolkit", "httpx"]) == "httpx-toolkit"


def test_run_tool_command_relative_binary_resolved_against_cwd(tmp_path):
    script = tmp_path / "myscript"
    script.write_text("#!/bin/sh\necho relative_ok\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    result = run_tool_command(["./myscript"], cwd=str(tmp_path), use_cache=False)
    assert result["success"] is True
    assert "relative_ok" in result["output"]


def test_run_tool_command_relative_binary_not_found_without_cwd():
    result = run_tool_command(["./myscript"], use_cache=False)
    assert result["success"] is False
    assert "not found" in result["error"]
