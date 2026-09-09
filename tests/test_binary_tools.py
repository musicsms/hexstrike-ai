import pytest
from pathlib import Path
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_gdb_analyze_handler_invocation_with_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_analyze")
    assert tool is not None
    assert tool.category == "binary"
    assert tool.endpoint == "/api/tools/gdb"

    res = tool.handler(binary="/tmp/target", commands="run\nbt", additional_args="-nx")
    assert res["success"] is True
    assert captured["cmd"] == ["gdb", "/tmp/target", "-x", "/tmp/gdb_commands.txt", "-nx", "-batch"]
    assert Path("/tmp/gdb_commands.txt").exists() is False


def test_gdb_analyze_handler_invocation_no_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_analyze")

    res = tool.handler(binary="/tmp/target", script_file="/tmp/script.gdb")
    assert res["success"] is True
    assert captured["cmd"] == ["gdb", "/tmp/target", "-x", "/tmp/script.gdb", "-batch"]


def test_ghidra_analyze_handler_invocation(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("ghidra_analyze")
    assert tool is not None
    assert tool.endpoint == "/api/tools/ghidra"

    res = tool.handler(binary="/tmp/target", project_name="proj1", analysis_timeout=120, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == [
        "analyzeHeadless", "/tmp/ghidra_projects/proj1", "proj1",
        "-import", "/tmp/target", "-deleteProject",
        "-postScript", "ExportXml.java", "/tmp/ghidra_projects/proj1/analysis.xml",
        "-v",
    ]
    assert Path("/tmp/ghidra_projects/proj1").is_dir()


def test_ropgadget_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("ropgadget_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/ropgadget"

    res = tool.handler(binary="/tmp/target", gadget_type="pop", additional_args="--depth 5")
    assert res["success"] is True
    assert captured["cmd"] == ["ROPgadget", "--binary", "/tmp/target", "--only", "pop", "--depth", "5"]


def test_checksec_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("checksec_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/checksec"

    res = tool.handler(binary="/tmp/target")
    assert res["success"] is True
    assert captured["cmd"] == ["checksec", "--file=/tmp/target"]


def test_xxd_dump_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("xxd_dump")
    assert tool is not None
    assert tool.endpoint == "/api/tools/xxd"

    res = tool.handler(file_path="/tmp/f.bin", offset="16", length="64", additional_args="-c 8")
    assert res["success"] is True
    assert captured["cmd"] == ["xxd", "-s", "16", "-l", "64", "-c", "8", "/tmp/f.bin"]


def test_strings_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("strings_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/strings"

    res = tool.handler(file_path="/tmp/f.bin", min_len=8, additional_args="-a")
    assert res["success"] is True
    assert captured["cmd"] == ["strings", "-n", "8", "-a", "/tmp/f.bin"]


def test_objdump_scan_handler_invocation_disassemble(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("objdump_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/objdump"

    res = tool.handler(binary="/tmp/target", additional_args="-C")
    assert res["success"] is True
    assert captured["cmd"] == ["objdump", "-d", "-C", "/tmp/target"]


def test_objdump_scan_handler_invocation_headers(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("objdump_scan")

    res = tool.handler(binary="/tmp/target", disassemble=False)
    assert res["success"] is True
    assert captured["cmd"] == ["objdump", "-x", "/tmp/target"]


def test_ropper_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("ropper_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/ropper"

    res = tool.handler(binary="/tmp/target", gadget_type="jop", quality=3, arch="x86_64", search_string="pop rdi", additional_args="--nocolor")
    assert res["success"] is True
    assert captured["cmd"] == [
        "ropper", "--file", "/tmp/target", "--jop",
        "--quality", "3", "--arch", "x86_64", "--search", "pop rdi", "--nocolor",
    ]


def test_ropper_scan_handler_invocation_defaults(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("ropper_scan")

    res = tool.handler(binary="/tmp/target")
    assert res["success"] is True
    assert captured["cmd"] == ["ropper", "--file", "/tmp/target", "--rop"]


def test_pwninit_setup_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwninit_setup")
    assert tool is not None
    assert tool.endpoint == "/api/tools/pwninit"

    res = tool.handler(binary="/tmp/target", libc="/tmp/libc.so.6", ld="/tmp/ld.so", additional_args="--force")
    assert res["success"] is True
    assert captured["cmd"] == [
        "pwninit", "--bin", "/tmp/target", "--libc", "/tmp/libc.so.6",
        "--ld", "/tmp/ld.so", "--template", "python", "--force",
    ]


def test_pwninit_setup_handler_invocation_no_template(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwninit_setup")

    res = tool.handler(binary="/tmp/target", template_type=None)
    assert res["success"] is True
    assert captured["cmd"] == ["pwninit", "--bin", "/tmp/target"]


def test_one_gadget_find_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("one_gadget_find")
    assert tool is not None
    assert tool.endpoint == "/api/tools/one-gadget"

    res = tool.handler(libc_path="/tmp/libc.so.6", level=2, additional_args="--raw")
    assert res["success"] is True
    assert captured["cmd"] == ["one_gadget", "/tmp/libc.so.6", "--level", "2", "--raw"]


def test_binary_category_has_11_tools():
    binary_tools = ToolRegistry.get_by_category("binary")
    assert len(binary_tools) == 11
    names = {t.name for t in binary_tools}
    assert names == {
        "radare2_analyze", "gdb_analyze", "ghidra_analyze", "ropgadget_scan",
        "checksec_scan", "xxd_dump", "strings_scan", "objdump_scan",
        "ropper_scan", "pwninit_setup", "one_gadget_find",
    }
