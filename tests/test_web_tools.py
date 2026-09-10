import pytest
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager
import hexstrike.tools


def _mock_execute(monkeypatch):
    """Bypass real binary lookup and subprocess execution, capture the built command."""
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)
    return captured


def test_arjun_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("arjun_scan")
    assert tool is not None
    assert tool.category == "web"
    assert tool.endpoint == "/api/tools/arjun"

    res = tool.handler(
        url="http://x.com", method="POST", wordlist="/tmp/wl.txt",
        delay=2, threads=10, stable=True, additional_args="--include X",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "arjun", "-u", "http://x.com", "-m", "POST", "-t", "10",
        "-w", "/tmp/wl.txt", "-d", "2", "--stable", "--include", "X",
    ]


def test_dalfox_scan_handler_invocation_url_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dalfox_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dalfox"

    res = tool.handler(
        url="http://x.com", blind=True, mining_dom=True, mining_dict=True,
        custom_payload="<script>", additional_args="--silence",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "dalfox", "url", "http://x.com", "--blind", "--mining-dom", "--mining-dict",
        "--custom-payload", "<script>", "--silence",
    ]


def test_dalfox_scan_handler_invocation_pipe_mode(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dalfox_scan")

    res = tool.handler(pipe_mode=True, mining_dom=False, mining_dict=False)
    assert res["success"] is True
    assert captured["cmd"] == ["dalfox", "pipe"]


def test_dirb_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dirb_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dirb"

    res = tool.handler(url="http://x.com", additional_args="-S")
    assert res["success"] is True
    assert captured["cmd"] == ["dirb", "http://x.com", "/usr/share/wordlists/dirb/common.txt", "-S"]


def test_dirsearch_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dirsearch_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dirsearch"

    res = tool.handler(url="http://x.com", extensions="php", wordlist="/tmp/wl.txt", threads=5, recursive=True, additional_args="-f")
    assert res["success"] is True
    assert captured["cmd"] == ["dirsearch", "-u", "http://x.com", "-e", "php", "-w", "/tmp/wl.txt", "-t", "5", "-r", "-f"]


def test_dotdotpwn_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("dotdotpwn_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/dotdotpwn"

    res = tool.handler(target="10.0.0.1", module="ftp", additional_args="-t 300")
    assert res["success"] is True
    assert captured["cmd"] == ["dotdotpwn", "-m", "ftp", "-h", "10.0.0.1", "-t", "300", "-b"]


def test_feroxbuster_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("feroxbuster_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/feroxbuster"

    res = tool.handler(url="http://x.com", wordlist="/tmp/wl.txt", threads=20, additional_args="-A")
    assert res["success"] is True
    assert captured["cmd"] == ["feroxbuster", "-u", "http://x.com", "-w", "/tmp/wl.txt", "-t", "20", "-A"]


def test_gau_discover_handler_invocation_default_providers(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gau_discover")
    assert tool is not None
    assert tool.endpoint == "/api/tools/gau"

    res = tool.handler(domain="example.com", additional_args="--threads 5")
    assert res["success"] is True
    assert captured["cmd"] == [
        "gau", "example.com", "--subs",
        "--blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
        "--threads", "5",
    ]


def test_gau_discover_handler_invocation_custom_providers(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("gau_discover")

    res = tool.handler(domain="example.com", providers="wayback", include_subs=False, blacklist="")
    assert res["success"] is True
    assert captured["cmd"] == ["gau", "example.com", "--providers", "wayback"]


def test_httpx_probe_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("httpx_probe")
    assert tool is not None
    assert tool.endpoint == "/api/tools/httpx"

    res = tool.handler(
        target="http://x.com", probe=True, tech_detect=True, status_code=True,
        content_length=True, title=True, web_server=True, threads=25, additional_args="-json",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "httpx", "-l", "http://x.com", "-t", "25",
        "-probe", "-tech-detect", "-sc", "-cl", "-title", "-server", "-json",
    ]


def test_jaeles_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("jaeles_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/jaeles"

    res = tool.handler(url="http://x.com", signatures="/tmp/sigs", config="/tmp/cfg", threads=5, timeout=10, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == [
        "jaeles", "scan", "-u", "http://x.com", "-c", "5", "--timeout", "10",
        "-s", "/tmp/sigs", "--config", "/tmp/cfg", "-v",
    ]


def test_katana_crawl_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("katana_crawl")
    assert tool is not None
    assert tool.endpoint == "/api/tools/katana"

    res = tool.handler(url="http://x.com", depth=5, js_crawl=True, form_extraction=True, output_format="json", additional_args="-silent")
    assert res["success"] is True
    assert captured["cmd"] == ["katana", "-u", "http://x.com", "-d", "5", "-jc", "-fx", "-jsonl", "-silent"]


def test_nikto_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nikto_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/nikto"

    res = tool.handler(target="http://x.com", additional_args="-Tuning 1")
    assert res["success"] is True
    assert captured["cmd"] == ["nikto", "-h", "http://x.com", "-Tuning", "1"]


def test_nuclei_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("nuclei_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/nuclei"

    res = tool.handler(target="http://x.com", severity="high", tags="cve", template="/tmp/t.yaml", additional_args="-rl 10")
    assert res["success"] is True
    assert captured["cmd"] == ["nuclei", "-u", "http://x.com", "-severity", "high", "-tags", "cve", "-t", "/tmp/t.yaml", "-rl", "10"]


def test_paramspider_mine_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("paramspider_mine")
    assert tool is not None
    assert tool.endpoint == "/api/tools/paramspider"

    res = tool.handler(domain="example.com", level=3, exclude="png,jpg", output="/tmp/out.txt", additional_args="-q")
    assert res["success"] is True
    assert captured["cmd"] == ["paramspider", "-d", "example.com", "-l", "3", "--exclude", "png,jpg", "-o", "/tmp/out.txt", "-q"]


def test_wafw00f_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("wafw00f_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/wafw00f"

    res = tool.handler(target="http://x.com", additional_args="-a")
    assert res["success"] is True
    assert captured["cmd"] == ["wafw00f", "http://x.com", "-a"]


def test_waybackurls_discover_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("waybackurls_discover")
    assert tool is not None
    assert tool.endpoint == "/api/tools/waybackurls"

    res = tool.handler(domain="example.com", get_versions=True, no_subs=True, additional_args="-d")
    assert res["success"] is True
    assert captured["cmd"] == ["waybackurls", "example.com", "--get-versions", "--no-subs", "-d"]


def test_wfuzz_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("wfuzz_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/wfuzz"

    res = tool.handler(url="http://x.com/FUZZ", wordlist="/tmp/wl.txt", additional_args="-c")
    assert res["success"] is True
    assert captured["cmd"] == ["wfuzz", "-w", "/tmp/wl.txt", "http://x.com/FUZZ", "-c"]


def test_wpscan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("wpscan_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/wpscan"

    res = tool.handler(url="http://x.com", additional_args="--enumerate p")
    assert res["success"] is True
    assert captured["cmd"] == ["wpscan", "--url", "http://x.com", "--enumerate", "p"]


def test_x8_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("x8_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/x8"

    res = tool.handler(url="http://x.com", wordlist="/tmp/wl.txt", method="POST", body="a=1", headers="X-Test: 1", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["x8", "-u", "http://x.com", "-w", "/tmp/wl.txt", "-X", "POST", "-b", "a=1", "-H", "X-Test: 1", "-v"]


def test_xsser_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("xsser_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/xsser"

    res = tool.handler(url="http://x.com", params="id=1", additional_args="--Fp")
    assert res["success"] is True
    assert captured["cmd"] == ["xsser", "--url", "http://x.com", "--param=id=1", "--Fp"]


def test_zap_scan_handler_invocation_quickscan(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("zap_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/zap"

    res = tool.handler(target="http://x.com", format="xml", output_file="/tmp/out", api_key="KEY123", additional_args="-cmd")
    assert res["success"] is True
    assert captured["cmd"] == [
        "zaproxy", "-cmd", "-quickurl", "http://x.com",
        "-quickout", "xml", "-quickprogress", "-dir", "/tmp/out",
        "-config", "api.key=KEY123", "-cmd",
    ]


def test_zap_scan_handler_invocation_daemon(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("zap_scan")

    res = tool.handler(daemon=True, host="127.0.0.1", port="9090", api_key="KEY123")
    assert res["success"] is True
    assert captured["cmd"] == ["zaproxy", "-daemon", "-host", "127.0.0.1", "-port", "9090", "-config", "api.key=KEY123"]


def test_anew_process_handler_invocation(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("anew_process")
    assert tool is not None
    assert tool.category == "web"
    assert tool.endpoint == "/api/tools/anew"

    res = tool.handler(input_data="line1\nline2", output_file="/tmp/seen.txt", additional_args="-q")
    assert res["success"] is True
    assert captured["cmd"] == ["anew", "/tmp/seen.txt", "-q"]
    assert captured["kwargs"]["stdin_input"] == "line1\nline2"


def test_qsreplace_process_handler_invocation(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("qsreplace_process")
    assert tool is not None
    assert tool.endpoint == "/api/tools/qsreplace"

    res = tool.handler(urls="http://a.com?x=1\nhttp://b.com?y=2", replacement="XSS", additional_args="-appendmode")
    assert res["success"] is True
    assert captured["cmd"] == ["qsreplace", "XSS", "-appendmode"]
    assert captured["kwargs"]["stdin_input"] == "http://a.com?x=1\nhttp://b.com?y=2"


def test_uro_filter_handler_invocation(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("uro_filter")
    assert tool is not None
    assert tool.endpoint == "/api/tools/uro"

    res = tool.handler(urls="http://a.com/1\nhttp://a.com/2", whitelist="a.com", blacklist="b.com", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["uro", "--whitelist", "a.com", "--blacklist", "b.com", "-v"]
    assert captured["kwargs"]["stdin_input"] == "http://a.com/1\nhttp://a.com/2"


def test_web_category_has_26_tools():
    from hexstrike.core.registry import ToolRegistry
    import hexstrike.tools
    web_tools = ToolRegistry.get_by_category("web")
    assert len(web_tools) == 26
    names = {t.name for t in web_tools}
    assert names == {
        "ffuf_fuzz", "gobuster_dir", "sqlmap_scan",
        "arjun_scan", "dalfox_scan", "dirb_scan", "dirsearch_scan", "dotdotpwn_scan",
        "feroxbuster_scan", "gau_discover", "httpx_probe", "jaeles_scan", "katana_crawl",
        "nikto_scan", "nuclei_scan", "paramspider_mine", "wafw00f_scan",
        "waybackurls_discover", "wfuzz_scan", "wpscan_scan", "x8_scan", "xsser_scan", "zap_scan",
        "anew_process", "qsreplace_process", "uro_filter",
    }
