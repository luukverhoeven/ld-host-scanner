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
