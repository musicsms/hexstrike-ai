from hexstrike.core.resource_monitor import ResourceMonitor


class FakeMemory:
    percent = 42.0
    available = 4 * 1024 ** 3


class FakeDisk:
    percent = 55.0
    free = 100 * 1024 ** 3


class FakeNetwork:
    bytes_sent = 1000
    bytes_recv = 2000


def _patch_psutil(monkeypatch, cpu=10.0):
    import hexstrike.core.resource_monitor as rm
    monkeypatch.setattr(rm.psutil, "cpu_percent", lambda interval=None: cpu)
    monkeypatch.setattr(rm.psutil, "virtual_memory", lambda: FakeMemory())
    monkeypatch.setattr(rm.psutil, "disk_usage", lambda path: FakeDisk())
    monkeypatch.setattr(rm.psutil, "net_io_counters", lambda: FakeNetwork())


def test_get_current_usage_shape(monkeypatch):
    _patch_psutil(monkeypatch, cpu=25.0)
    monitor = ResourceMonitor()
    usage = monitor.get_current_usage()
    assert usage["cpu_percent"] == 25.0
    assert usage["memory_percent"] == 42.0
    assert usage["memory_available_gb"] == 4.0
    assert usage["disk_percent"] == 55.0
    assert usage["disk_free_gb"] == 100.0
    assert usage["network_bytes_sent"] == 1000
    assert usage["network_bytes_recv"] == 2000
    assert "timestamp" in usage


def test_get_usage_trends_empty_with_fewer_than_two_samples(monkeypatch):
    _patch_psutil(monkeypatch)
    monitor = ResourceMonitor()
    assert monitor.get_usage_trends() == {}
    monitor.get_current_usage()
    assert monitor.get_usage_trends() == {}


def test_get_usage_trends_averages_recent_samples(monkeypatch):
    monitor = ResourceMonitor()
    import hexstrike.core.resource_monitor as rm
    for cpu in (10.0, 20.0, 30.0):
        _patch_psutil(monkeypatch, cpu=cpu)
        monitor.get_current_usage()
    trends = monitor.get_usage_trends()
    assert trends["measurements"] == 3
    assert trends["cpu_avg_recent"] == 20.0
    assert trends["memory_avg_recent"] == 42.0


def test_history_capped_at_history_size(monkeypatch):
    _patch_psutil(monkeypatch)
    monitor = ResourceMonitor(history_size=3)
    for _ in range(5):
        monitor.get_current_usage()
    assert monitor.get_usage_trends()["measurements"] == 3
