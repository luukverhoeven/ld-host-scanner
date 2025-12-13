"""Tests for host checker utilities."""

from __future__ import annotations

import asyncio
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_check_host_dns_returns_ip():
    from src.scanner import host_checker

    loop = MagicMock()
    loop.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 0))])

    with patch.object(asyncio, "get_running_loop", return_value=loop):
        ip = await host_checker.check_host_dns("example.com")

    assert ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_check_host_dns_handles_gaierror():
    from src.scanner import host_checker

    loop = MagicMock()
    loop.getaddrinfo = AsyncMock(side_effect=socket.gaierror("nope"))

    with patch.object(asyncio, "get_running_loop", return_value=loop):
        ip = await host_checker.check_host_dns("example.com")

    assert ip is None


@pytest.mark.asyncio
async def test_check_host_tcp_connect_success_closes_writer():
    from src.scanner import host_checker

    writer = MagicMock()
    writer.wait_closed = AsyncMock()

    with patch.object(asyncio, "open_connection", return_value=AsyncMock()), \
         patch.object(asyncio, "wait_for", new=AsyncMock(return_value=(None, writer))):
        ok = await host_checker.check_host_tcp_connect("example.com", port=443, timeout=0.1)

    assert ok is True
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited()


@pytest.mark.asyncio
async def test_check_host_tcp_connect_refused_counts_as_up():
    from src.scanner import host_checker

    with patch.object(asyncio, "open_connection", return_value=AsyncMock()), \
         patch.object(asyncio, "wait_for", new=AsyncMock(side_effect=ConnectionRefusedError())):
        ok = await host_checker.check_host_tcp_connect("example.com", port=1, timeout=0.1)
    assert ok is True


@pytest.mark.asyncio
async def test_check_host_tcp_connect_timeout_is_false():
    from src.scanner import host_checker

    with patch.object(asyncio, "open_connection", return_value=AsyncMock()), \
         patch.object(asyncio, "wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError())):
        ok = await host_checker.check_host_tcp_connect("example.com", port=1, timeout=0.1)
    assert ok is False


@pytest.mark.asyncio
async def test_check_host_ping_no_ping_binary():
    from src.scanner import host_checker

    with patch("shutil.which", return_value=None):
        ok = await host_checker.check_host_ping("example.com")
    assert ok is False


@pytest.mark.asyncio
async def test_check_host_ping_success_linux():
    from src.scanner import host_checker

    proc = SimpleNamespace(wait=AsyncMock(return_value=0))

    with patch("shutil.which", return_value="/bin/ping"), \
         patch("platform.system", return_value="Linux"), \
         patch.object(asyncio, "create_subprocess_exec", new=AsyncMock(return_value=proc)):
        ok = await host_checker.check_host_ping("example.com", timeout=1.0, count=1)
    assert ok is True


@pytest.mark.asyncio
async def test_check_host_ping_success_darwin_uses_ms_timeout():
    from src.scanner import host_checker

    proc = SimpleNamespace(wait=AsyncMock(return_value=0))

    with patch("shutil.which", return_value="/sbin/ping"), \
         patch("platform.system", return_value="Darwin"), \
         patch.object(asyncio, "create_subprocess_exec", new=AsyncMock(return_value=proc)) as subproc_mock:
        ok = await host_checker.check_host_ping("example.com", timeout=1.5, count=1)

    assert ok is True
    args = subproc_mock.call_args.args
    assert "-W" in args


@pytest.mark.asyncio
async def test_quick_host_check_online_via_ping(monkeypatch):
    from src.scanner import host_checker

    monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
    monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
    monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=True))

    with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[22, 443])):
        result = await host_checker.quick_host_check("example.com")

    assert result["status"] == "online"
    assert result["ping_reachable"] is True


@pytest.mark.asyncio
async def test_quick_host_check_dns_only_when_no_ping_or_tcp(monkeypatch):
    from src.scanner import host_checker

    monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
    monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
    monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=False))
    monkeypatch.setattr(host_checker, "check_host_tcp_connect", AsyncMock(return_value=False))

    with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[12345])):
        result = await host_checker.quick_host_check("example.com")

    assert result["status"] == "dns_only"
    assert result["dns_resolved"] is True
    assert result["tcp_reachable"] is False


class TestCheckHostDnsEdgeCases:
    """Edge case tests for DNS resolution."""

    @pytest.mark.asyncio
    async def test_check_host_dns_empty_result(self):
        """Test DNS resolution with empty result list."""
        from src.scanner import host_checker

        loop = MagicMock()
        loop.getaddrinfo = AsyncMock(return_value=[])

        with patch.object(asyncio, "get_running_loop", return_value=loop):
            ip = await host_checker.check_host_dns("example.com")

        assert ip is None

    @pytest.mark.asyncio
    async def test_check_host_dns_unexpected_exception(self):
        """Test DNS resolution with unexpected exception."""
        from src.scanner import host_checker

        loop = MagicMock()
        loop.getaddrinfo = AsyncMock(side_effect=RuntimeError("Unexpected error"))

        with patch.object(asyncio, "get_running_loop", return_value=loop):
            ip = await host_checker.check_host_dns("example.com")

        assert ip is None


class TestCheckHostTcpConnectEdgeCases:
    """Edge case tests for TCP connection check."""

    @pytest.mark.asyncio
    async def test_check_host_tcp_connect_generic_exception(self):
        """Test TCP connect with generic exception."""
        from src.scanner import host_checker

        with patch.object(asyncio, "open_connection", return_value=AsyncMock()), \
             patch.object(asyncio, "wait_for", new=AsyncMock(side_effect=OSError("Network unreachable"))):
            ok = await host_checker.check_host_tcp_connect("example.com", port=443, timeout=0.1)

        assert ok is False

    @pytest.mark.asyncio
    async def test_check_host_tcp_connect_writer_cleanup_exception(self):
        """Test TCP connect handles writer cleanup exception gracefully."""
        from src.scanner import host_checker

        writer = MagicMock()
        writer.wait_closed = AsyncMock(side_effect=RuntimeError("Cleanup failed"))

        with patch.object(asyncio, "open_connection", return_value=AsyncMock()), \
             patch.object(asyncio, "wait_for", new=AsyncMock(return_value=(None, writer))):
            ok = await host_checker.check_host_tcp_connect("example.com", port=443, timeout=0.1)

        assert ok is True  # Should still return True despite cleanup error


class TestCheckHostPingEdgeCases:
    """Edge case tests for ICMP ping check."""

    @pytest.mark.asyncio
    async def test_check_host_ping_failure_nonzero_exit(self):
        """Test ping failure with non-zero exit code."""
        from src.scanner import host_checker

        proc = SimpleNamespace(wait=AsyncMock(return_value=1))

        with patch("shutil.which", return_value="/bin/ping"), \
             patch("platform.system", return_value="Linux"), \
             patch.object(asyncio, "create_subprocess_exec", new=AsyncMock(return_value=proc)):
            ok = await host_checker.check_host_ping("example.com", timeout=1.0, count=1)

        assert ok is False

    @pytest.mark.asyncio
    async def test_check_host_ping_exception_during_execution(self):
        """Test ping handles exception during subprocess execution."""
        from src.scanner import host_checker

        with patch("shutil.which", return_value="/bin/ping"), \
             patch("platform.system", return_value="Linux"), \
             patch.object(asyncio, "create_subprocess_exec", new=AsyncMock(side_effect=OSError("Subprocess failed"))):
            ok = await host_checker.check_host_ping("example.com", timeout=1.0, count=1)

        assert ok is False


class TestQuickHostCheckEdgeCases:
    """Edge case tests for quick host check."""

    @pytest.mark.asyncio
    async def test_quick_host_check_online_via_tcp_fallback(self, monkeypatch):
        """Test host is online via TCP when ping fails."""
        from src.scanner import host_checker

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=False))
        monkeypatch.setattr(host_checker, "check_host_tcp_connect", AsyncMock(return_value=True))

        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[22, 443])):
            result = await host_checker.quick_host_check("example.com")

        assert result["status"] == "online"
        assert result["ping_reachable"] is False
        assert result["tcp_reachable"] is True
        assert result["method"] == "tcp"

    @pytest.mark.asyncio
    async def test_quick_host_check_offline_no_dns(self, monkeypatch):
        """Test host is offline when DNS resolution fails."""
        from src.scanner import host_checker

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value=None))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=False))
        monkeypatch.setattr(host_checker, "check_host_tcp_connect", AsyncMock(return_value=False))

        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[])):
            result = await host_checker.quick_host_check("example.com")

        assert result["status"] == "offline"
        assert result["dns_resolved"] is False
        assert result["method"] is None

    @pytest.mark.asyncio
    async def test_quick_host_check_uses_default_target(self, monkeypatch):
        """Test quick host check uses default target from settings."""
        from src.scanner import host_checker

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="default.example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=True))

        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[])):
            result = await host_checker.quick_host_check()  # No target specified

        assert result["target"] == "default.example.com"
        assert result["status"] == "online"

    @pytest.mark.asyncio
    async def test_quick_host_check_method_field_icmp(self, monkeypatch):
        """Test method field is 'icmp' when ping succeeds."""
        from src.scanner import host_checker

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=True))

        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[])):
            result = await host_checker.quick_host_check("example.com")

        assert result["method"] == "icmp"

    @pytest.mark.asyncio
    async def test_quick_host_check_method_field_dns(self, monkeypatch):
        """Test method field is 'dns' for dns_only status."""
        from src.scanner import host_checker

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=False))
        monkeypatch.setattr(host_checker, "check_host_tcp_connect", AsyncMock(return_value=False))

        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[])):
            result = await host_checker.quick_host_check("example.com")

        assert result["status"] == "dns_only"
        assert result["method"] == "dns"

    @pytest.mark.asyncio
    async def test_quick_host_check_fallback_ports_combined(self, monkeypatch):
        """Test that discovered ports and common ports are combined for TCP check."""
        from src.scanner import host_checker

        tcp_ports_tried = []

        async def mock_tcp_connect(target, port):
            tcp_ports_tried.append(port)
            return False

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=False))
        monkeypatch.setattr(host_checker, "check_host_tcp_connect", mock_tcp_connect)

        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[8443, 9000])):
            result = await host_checker.quick_host_check("example.com")

        # Should try discovered ports first, then common ports
        assert 8443 in tcp_ports_tried
        assert 9000 in tcp_ports_tried
        assert 443 in tcp_ports_tried
        assert 80 in tcp_ports_tried

    @pytest.mark.asyncio
    async def test_quick_host_check_stops_on_first_tcp_success(self, monkeypatch):
        """Test TCP check stops on first successful port."""
        from src.scanner import host_checker

        tcp_ports_tried = []

        async def mock_tcp_connect(target, port):
            tcp_ports_tried.append(port)
            return port == 443  # Succeed on port 443

        monkeypatch.setattr(host_checker, "settings", SimpleNamespace(target_host="example.com"))
        monkeypatch.setattr(host_checker, "check_host_dns", AsyncMock(return_value="1.2.3.4"))
        monkeypatch.setattr(host_checker, "check_host_ping", AsyncMock(return_value=False))
        monkeypatch.setattr(host_checker, "check_host_tcp_connect", mock_tcp_connect)

        # No discovered ports, will try common ports: 443, 80, 22, 8080
        with patch("src.storage.database.get_open_ports_from_last_scan", new=AsyncMock(return_value=[])):
            result = await host_checker.quick_host_check("example.com")

        assert result["tcp_reachable"] is True
        # Should stop at 443, not try further ports
        assert tcp_ports_tried == [443]
