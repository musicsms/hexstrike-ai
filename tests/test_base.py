import os
import stat
from hexstrike.tools.base import run_tool_command


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
