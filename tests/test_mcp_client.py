import requests
from hexstrike.mcp.client import HexStrikeClient


def test_check_health_success(monkeypatch):
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"status": "healthy"}

    monkeypatch.setattr(requests, "get", lambda url, timeout=None: FakeResponse())
    assert client.check_health() == {"status": "healthy"}


def test_check_health_non_200(monkeypatch):
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")

    class FakeResponse:
        status_code = 503

        def json(self):
            raise AssertionError("json() should not be called on a non-200 response")

    monkeypatch.setattr(requests, "get", lambda url, timeout=None: FakeResponse())
    assert client.check_health() == {"error": "Server returned status 503"}


def test_check_health_request_exception(monkeypatch):
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")

    def raise_connection_error(url, timeout=None):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(requests, "get", raise_connection_error)
    result = client.check_health()
    assert result == {"error": "connection refused"}


def test_execute_tool_success(monkeypatch):
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")
    captured = {}

    class FakeResponse:
        def json(self):
            return {"success": True, "output": "done"}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(requests, "post", fake_post)
    result = client.execute_tool("/api/tools/nmap", {"target": "127.0.0.1"})

    assert result == {"success": True, "output": "done"}
    assert captured["url"] == "http://127.0.0.1:8888/api/tools/nmap"
    assert captured["json"] == {"target": "127.0.0.1"}
    assert captured["timeout"] == client.timeout


def test_execute_tool_request_exception(monkeypatch):
    client = HexStrikeClient(server_url="http://127.0.0.1:8888")

    def raise_timeout(url, json=None, timeout=None):
        raise requests.exceptions.Timeout("timed out")

    monkeypatch.setattr(requests, "post", raise_timeout)
    result = client.execute_tool("/api/tools/nmap", {"target": "127.0.0.1"})
    assert result == {"success": False, "error": "timed out"}
