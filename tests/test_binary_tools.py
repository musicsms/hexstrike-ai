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


def test_pwntools_exploit_handler_invocation_script_content(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwntools_exploit")
    assert tool is not None
    assert tool.category == "binary"
    assert tool.endpoint == "/api/tools/pwntools"

    res = tool.handler(script_content="print('hi')", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["python3", "/tmp/pwntools_exploit.py", "-v"]
    assert Path("/tmp/pwntools_exploit.py").exists() is False


def test_pwntools_exploit_handler_invocation_generated_template(monkeypatch):
    written = {}
    original_write_text = Path.write_text

    def capture_write_text(self, content, *a, **kw):
        if str(self) == "/tmp/pwntools_exploit.py":
            written["content"] = content
        return original_write_text(self, content, *a, **kw)

    monkeypatch.setattr(Path, "write_text", capture_write_text)
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("pwntools_exploit")

    res = tool.handler(target_binary="/tmp/exploit")
    assert res["success"] is True
    assert captured["cmd"] == ["python3", "/tmp/pwntools_exploit.py"]

    target_binary, target_host, target_port = "/tmp/exploit", "", 0
    expected = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
    assert written["content"] == expected


def test_angr_analyze_handler_invocation_symbolic(monkeypatch):
    written = {}
    original_write_text = Path.write_text

    def capture_write_text(self, content, *a, **kw):
        if str(self) == "/tmp/angr_analysis.py":
            written["content"] = content
        return original_write_text(self, content, *a, **kw)

    monkeypatch.setattr(Path, "write_text", capture_write_text)

    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("angr_analyze")
    assert tool is not None
    assert tool.endpoint == "/api/tools/angr"

    res = tool.handler(binary="/tmp/target", find_address="0x401000", avoid_addresses="0x402000,0x403000")
    assert res["success"] is True
    assert captured["cmd"] == ["python3", "/tmp/angr_analysis.py"]
    assert captured["kwargs"]["timeout"] == 600

    binary = "/tmp/target"
    base = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
    find_address, avoid_addresses = "0x401000", "0x402000,0x403000"
    base += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
    assert written["content"] == base


def test_angr_analyze_handler_invocation_cfg(monkeypatch):
    written = {}
    original_write_text = Path.write_text

    def capture_write_text(self, content, *a, **kw):
        if str(self) == "/tmp/angr_analysis.py":
            written["content"] = content
        return original_write_text(self, content, *a, **kw)

    monkeypatch.setattr(Path, "write_text", capture_write_text)
    captured = _mock_execute(monkeypatch)

    tool = ToolRegistry.get("angr_analyze")
    res = tool.handler(binary="/tmp/target", analysis_type="cfg")
    assert res["success"] is True

    binary = "/tmp/target"
    base = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
    base += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""
    assert written["content"] == base


def test_gdb_peda_analyze_handler_invocation_with_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_peda_analyze")
    assert tool is not None
    assert tool.endpoint == "/api/tools/gdb-peda"

    res = tool.handler(binary="/tmp/target", commands="run\nbt", additional_args="-nx")
    assert res["success"] is True
    assert captured["cmd"] == ["gdb", "-q", "/tmp/target", "-x", "/tmp/gdb_peda_commands.txt", "-nx"]
    assert Path("/tmp/gdb_peda_commands.txt").exists() is False


def test_gdb_peda_analyze_handler_invocation_no_commands(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gdb_peda_analyze")

    res = tool.handler(binary="/tmp/target", core_file="/tmp/core", attach_pid=1234)
    assert res["success"] is True
    assert captured["cmd"] == [
        "gdb", "-q", "/tmp/target", "/tmp/core", "-p", "1234",
        "-ex", "source ~/peda/peda.py", "-ex", "quit",
    ]


def test_libc_database_lookup_handler_invocation_find(monkeypatch):
    real_is_dir = Path.is_dir

    def fake_is_dir(self):
        if str(self) == "/opt/libc-database":
            return True
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", fake_is_dir)

    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("libc_database_lookup")
    assert tool is not None
    assert tool.category == "binary"
    assert tool.endpoint == "/api/tools/libc-database"

    res = tool.handler(action="find", symbols="printf:0x64 system:0x123", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["./find", "printf:0x64 system:0x123", "-v"]
    assert captured["kwargs"]["cwd"] == "/opt/libc-database"


def test_libc_database_lookup_handler_invocation_dump_home_fallback(monkeypatch):
    home_libc_dir = str(Path.home() / "libc-database")
    real_is_dir = Path.is_dir

    def fake_is_dir(self):
        if str(self) == "/opt/libc-database":
            return False
        if str(self) == home_libc_dir:
            return True
        return real_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", fake_is_dir)

    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("libc_database_lookup")
    res = tool.handler(action="dump", libc_id="libc6_2.31-0ubuntu9_amd64")
    assert res["success"] is True
    assert captured["cmd"] == ["./dump", "libc6_2.31-0ubuntu9_amd64"]
    assert captured["kwargs"]["cwd"] == home_libc_dir


def test_libc_database_lookup_handler_invocation_download_neither_dir_found(monkeypatch):
    monkeypatch.setattr(Path, "is_dir", lambda self: False)

    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("libc_database_lookup")
    res = tool.handler(action="download", libc_id="abc123")
    assert res["success"] is True
    assert captured["cmd"] == ["./download", "abc123"]
    assert captured["kwargs"]["cwd"] is None


def test_binary_category_has_15_tools():
    binary_tools = ToolRegistry.get_by_category("binary")
    assert len(binary_tools) == 15
    names = {t.name for t in binary_tools}
    assert names == {
        "radare2_analyze", "gdb_analyze", "ghidra_analyze", "ropgadget_scan",
        "checksec_scan", "xxd_dump", "strings_scan", "objdump_scan",
        "ropper_scan", "pwninit_setup", "one_gadget_find",
        "pwntools_exploit", "angr_analyze", "gdb_peda_analyze",
        "libc_database_lookup",
    }
