from pathlib import Path
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


def test_prowler_scan_handler_invocation(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("prowler_scan")
    assert tool is not None
    assert tool.category == "cloud"
    assert tool.endpoint == "/api/tools/prowler"

    output_dir = str(tmp_path / "prowler_output")
    res = tool.handler(
        provider="aws", profile="myprofile", region="us-east-1", checks="check1,check2",
        output_dir=output_dir, output_format="json", additional_args="-M csv",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "prowler", "aws",
        "--profile", "myprofile",
        "--region", "us-east-1",
        "--checks", "check1,check2",
        "--output-directory", output_dir,
        "--output-format", "json",
        "-M", "csv",
    ]
    assert res["output_directory"] == output_dir
    assert Path(output_dir).is_dir()


def test_trivy_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("trivy_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/trivy"

    res = tool.handler(
        target="myimage:latest", scan_type="image", output_format="json",
        severity="HIGH,CRITICAL", output_file="/tmp/out.json", additional_args="--timeout 5m",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "trivy", "image", "myimage:latest",
        "--format", "json", "--severity", "HIGH,CRITICAL", "--output", "/tmp/out.json",
        "--timeout", "5m",
    ]
    assert res["output_file"] == "/tmp/out.json"

    res2 = tool.handler(target="myimage:latest")
    assert "output_file" not in res2
    assert captured["cmd"] == ["trivy", "image", "myimage:latest", "--format", "json"]


def test_scout_suite_scan_handler_invocation_aws(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("scout_suite_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/scout-suite"

    report_dir = str(tmp_path / "scout-report")
    res = tool.handler(
        provider="aws", profile="myprofile", report_dir=report_dir,
        services="s3,ec2", exceptions="exc.json", additional_args="--no-browser",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "scout", "aws",
        "--profile", "myprofile",
        "--services", "s3,ec2",
        "--exceptions", "exc.json",
        "--report-dir", report_dir,
        "--no-browser",
    ]
    assert res["report_directory"] == report_dir
    assert Path(report_dir).is_dir()


def test_scout_suite_scan_handler_invocation_non_aws_skips_profile(monkeypatch, tmp_path):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("scout_suite_scan")

    report_dir = str(tmp_path / "scout-report-azure")
    res = tool.handler(provider="azure", profile="myprofile", report_dir=report_dir)
    assert res["success"] is True
    assert captured["cmd"] == ["scout", "azure", "--report-dir", report_dir]
    assert res["report_directory"] == report_dir
    assert Path(report_dir).is_dir()


def test_cloudmapper_run_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("cloudmapper_run")
    assert tool is not None
    assert tool.endpoint == "/api/tools/cloudmapper"

    res = tool.handler(action="collect", account="123456789", config="myconfig.json", additional_args="--verbose")
    assert res["success"] is True
    assert captured["cmd"] == ["cloudmapper", "collect", "--account", "123456789", "--config", "myconfig.json", "--verbose"]


def test_kube_hunter_scan_handler_invocation_target(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/kube-hunter"

    res = tool.handler(target="10.0.0.1", active=True, report="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--remote", "10.0.0.1", "--active", "--report", "json", "-v"]


def test_kube_hunter_scan_handler_invocation_default_pod(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")

    res = tool.handler(report="json")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--pod", "--report", "json"]


def test_kube_hunter_scan_handler_invocation_target_takes_priority_over_cidr(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_hunter_scan")

    res = tool.handler(target="10.0.0.1", cidr="10.0.0.0/24", report="json")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-hunter", "--remote", "10.0.0.1", "--report", "json"]
    assert "--cidr" not in captured["cmd"]


def test_kube_bench_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_bench_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/kube-bench"

    res = tool.handler(targets="master,node", version="1.23", config_dir="/etc/kube-bench", output_format="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == [
        "kube-bench", "--targets", "master,node", "--version", "1.23", "--config-dir", "/etc/kube-bench",
        "--outputfile", "/tmp/kube-bench-results.json", "--json", "-v",
    ]


def test_kube_bench_scan_handler_invocation_non_json_format(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("kube_bench_scan")

    res = tool.handler(output_format="junit")
    assert res["success"] is True
    assert captured["cmd"] == ["kube-bench", "--outputfile", "/tmp/kube-bench-results.junit", "--json"]


def test_docker_bench_security_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("docker_bench_security_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/docker-bench-security"

    res = tool.handler(checks="check1", exclude="check2", output_file="/tmp/custom.json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["docker-bench-security", "-c", "check1", "-e", "check2", "-l", "/tmp/custom.json", "-v"]
    assert res["output_file"] == "/tmp/custom.json"

    res2 = tool.handler()
    assert res2["output_file"] == "/tmp/docker-bench-results.json"
    assert captured["cmd"] == ["docker-bench-security", "-l", "/tmp/docker-bench-results.json"]


def test_falco_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("falco_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/falco"

    res = tool.handler(config_file="/tmp/falco.yaml", rules_file="/tmp/rules.yaml", output_format="json", duration=30, additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["timeout", "30", "falco", "--config", "/tmp/falco.yaml", "--rules", "/tmp/rules.yaml", "--json", "-v"]


def test_falco_scan_handler_invocation_non_json_format(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("falco_scan")

    res = tool.handler(output_format="text")
    assert res["success"] is True
    assert "--json" not in captured["cmd"]


def test_clair_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("clair_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/clair"

    res = tool.handler(image="myimage:latest", config="/tmp/clair.yaml", output_format="json", additional_args="-v")
    assert res["success"] is True
    assert captured["cmd"] == ["clairctl", "analyze", "myimage:latest", "--config", "/tmp/clair.yaml", "--format", "json", "-v"]


def test_checkov_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("checkov_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/checkov"

    res = tool.handler(
        directory="/tmp/iac", framework="terraform", check="CKV_AWS_1",
        skip_check="CKV_AWS_2", output_format="json", additional_args="--compact",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "checkov", "-d", "/tmp/iac",
        "--framework", "terraform", "--check", "CKV_AWS_1", "--skip-check", "CKV_AWS_2",
        "--output", "json", "--compact",
    ]


def test_terrascan_scan_handler_invocation(monkeypatch):
    captured = _mock_execute(monkeypatch)
    tool = ToolRegistry.get("terrascan_scan")
    assert tool is not None
    assert tool.endpoint == "/api/tools/terrascan"

    res = tool.handler(
        scan_type="terraform", iac_dir="/tmp/iac", policy_type="aws",
        output_format="json", severity="HIGH", additional_args="--non-recursive",
    )
    assert res["success"] is True
    assert captured["cmd"] == [
        "terrascan", "scan", "-t", "terraform", "-d", "/tmp/iac",
        "-p", "aws", "-o", "json", "--severity", "HIGH", "--non-recursive",
    ]


def test_pacu_run_handler_invocation(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("pacu_run")
    assert tool is not None
    assert tool.category == "cloud"
    assert tool.endpoint == "/api/tools/pacu"

    res = tool.handler(
        session_name="mysess", data_services="s3,ec2", regions="us-east-1",
        modules="iam__enum_users, s3__bucket_finder", additional_args="--force",
    )
    assert res["success"] is True
    assert captured["cmd"] == ["pacu", "--force"]
    assert captured["kwargs"]["stdin_input"] == (
        "set_session mysess\n"
        "data s3,ec2\n"
        "set_regions us-east-1\n"
        "run iam__enum_users\n"
        "run s3__bucket_finder\n"
        "exit"
    )


def test_pacu_run_handler_invocation_defaults(monkeypatch):
    captured = {}

    def fake_execute(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return {"success": True, "command": " ".join(cmd), "output": "", "cached": False}

    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    tool = ToolRegistry.get("pacu_run")
    res = tool.handler()
    assert res["success"] is True
    assert captured["cmd"] == ["pacu"]
    assert captured["kwargs"]["stdin_input"] == "set_session hexstrike_session\nexit"


def test_cloud_category_has_12_tools():
    cloud_tools = ToolRegistry.get_by_category("cloud")
    assert len(cloud_tools) == 12
    names = {t.name for t in cloud_tools}
    assert names == {
        "prowler_scan", "trivy_scan", "scout_suite_scan", "cloudmapper_run",
        "kube_hunter_scan", "kube_bench_scan", "docker_bench_security_scan",
        "falco_scan", "clair_scan", "checkov_scan", "terrascan_scan", "pacu_run",
    }
