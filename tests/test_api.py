import pytest
from hexstrike.api.app import create_app

@pytest.fixture
def client():
    app = create_app(debug=True)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "tools_status" in data
    assert "version" in data

def test_tools_list_endpoint(client):
    res = client.get("/api/tools")
    assert res.status_code == 200
    data = res.get_json()
    assert "tools" in data
    assert len(data["tools"]) > 0

def test_tool_execution_route(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", lambda cmd, **kwargs: {
        "success": True, "command": " ".join(cmd), "output": "ok", "cached": False
    })
    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

def test_tool_execution_route_get_method_uses_query_params(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", lambda cmd, **kwargs: {
        "success": True, "command": " ".join(cmd), "output": "ok", "cached": False
    })
    res = client.get("/api/tools/nmap?target=127.0.0.1")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

def test_tool_execution_route_ignores_unknown_params(client, monkeypatch):
    """A caller sending a legacy/unsupported field this tool never had
    should still get a real scan, not a 400. (Note: use_recovery is no
    longer an example of this — it's a recognized opt-in flag as of the
    failure-recovery-system plan's Task 7; see the use_recovery-specific
    tests below.)"""
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", lambda cmd, **kwargs: {
        "success": True, "command": " ".join(cmd), "output": "ok", "cached": False
    })
    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1", "legacy_option": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["ignored_params"] == ["legacy_option"]

def test_tool_execution_route_missing_required_argument_returns_400(client):
    res = client.post("/api/tools/nmap", json={})
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "Invalid arguments for nmap_scan" in data["error"]
    assert data["command"] == "nmap_scan"

def test_tool_execution_route_handler_exception_returns_500(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    def raise_runtime_error(cmd, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(default_process_manager, "execute_command", raise_runtime_error)
    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1"})
    assert res.status_code == 500
    data = res.get_json()
    assert data["success"] is False
    assert data["error"] == "boom"
    assert data["command"] == "nmap_scan"

def test_tool_execution_route_use_recovery_retries_then_succeeds(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    import hexstrike.core.recovery as recovery_module
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(recovery_module.time, "sleep", lambda seconds: None)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"success": False, "command": " ".join(cmd), "output": "", "error": "rate limit exceeded", "cached": False}
        return {"success": True, "command": " ".join(cmd), "output": "ok", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1", "use_recovery": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["recovery_info"]["attempts_made"] == 2
    assert calls["count"] == 2


def test_tool_execution_route_use_recovery_defaults_to_false(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        return {"success": True, "command": " ".join(cmd), "output": "ok", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "recovery_info" not in data
    assert calls["count"] == 1


def test_tool_execution_route_use_recovery_escalates_on_permission_denied(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        return {"success": False, "command": " ".join(cmd), "output": "", "error": "permission denied", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1", "use_recovery": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is False
    assert data["recovery_info"]["attempts_made"] == 1
    assert "human_escalation" in data
    assert calls["count"] == 1


def test_tool_execution_route_get_method_use_recovery_string_false_is_falsy(client, monkeypatch):
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)

    calls = {"count": 0}

    def fake_execute(cmd, **kwargs):
        calls["count"] += 1
        return {"success": False, "command": " ".join(cmd), "output": "", "error": "permission denied", "cached": False}

    monkeypatch.setattr(default_process_manager, "execute_command", fake_execute)

    res = client.get("/api/tools/nmap?target=127.0.0.1&use_recovery=false")
    assert res.status_code == 200
    data = res.get_json()
    assert "recovery_info" not in data
    assert calls["count"] == 1
