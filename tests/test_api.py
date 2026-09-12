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
    """A caller sending a legacy/unsupported field (e.g. use_recovery from the
    pre-refactor monolith's FailureRecoverySystem) should still get a real
    scan, not a 400 for an argument this tool never had."""
    from hexstrike.core.process import default_process_manager
    monkeypatch.setattr("hexstrike.tools.base.is_tool_available", lambda name: True)
    monkeypatch.setattr(default_process_manager, "execute_command", lambda cmd, **kwargs: {
        "success": True, "command": " ".join(cmd), "output": "ok", "cached": False
    })
    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1", "use_recovery": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["ignored_params"] == ["use_recovery"]

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
