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
    monkeypatch.setattr(default_process_manager, "execute_command", lambda cmd, **kwargs: {
        "success": True, "command": " ".join(cmd), "output": "ok", "cached": False
    })
    res = client.post("/api/tools/nmap", json={"target": "127.0.0.1"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
