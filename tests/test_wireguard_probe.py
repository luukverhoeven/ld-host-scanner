"""Tests for WireGuard probe utilities (no network)."""

from __future__ import annotations

import base64
import socket
import struct
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.scanner.wireguard_probe import (
    MESSAGE_TYPE_COOKIE_REPLY,
    MESSAGE_TYPE_HANDSHAKE_RESPONSE,
    WireGuardProbe,
)


def test_wireguard_packet_sizes():
    probe = WireGuardProbe(server_public_key_b64=None)
    header = probe._build_handshake_init_header()
    packet = probe._build_handshake_init()
    assert len(header) == 116
    assert len(packet) == 148


def test_wireguard_mac1_is_deterministic_for_same_inputs():
    server_key = b"\x01" * 32
    probe = WireGuardProbe(server_public_key_b64=base64.b64encode(server_key).decode("ascii"))
    header = probe._build_handshake_init_header()
    mac1_a = probe._compute_mac1(header)
    mac1_b = probe._compute_mac1(header)
    assert mac1_a == mac1_b
    assert len(mac1_a) == 16


def test_wireguard_probe_dns_error():
    probe = WireGuardProbe()
    with patch.object(socket, "gethostbyname", side_effect=socket.gaierror("no")):
        result = probe.probe("bad.host", 51820, timeout=0.01)
    assert result["verified"] is False
    assert result["response_type"] == "dns_error"


def test_wireguard_probe_cookie_reply_marks_verified():
    probe = WireGuardProbe()

    fake_sock = MagicMock()
    fake_sock.recvfrom.return_value = (struct.pack("<I", MESSAGE_TYPE_COOKIE_REPLY) + b"x" * 20, ("1.2.3.4", 51820))
    fake_sock.sendto.return_value = None

    with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
         patch.object(socket, "socket", return_value=fake_sock):
        result = probe.probe("example.com", 51820, timeout=0.01)

    assert result["verified"] is True
    assert result["response_type"] == "cookie_reply"


def test_wireguard_probe_handshake_response_marks_verified():
    probe = WireGuardProbe()

    fake_sock = MagicMock()
    fake_sock.recvfrom.return_value = (struct.pack("<I", MESSAGE_TYPE_HANDSHAKE_RESPONSE) + b"x" * 20, ("1.2.3.4", 51820))
    fake_sock.sendto.return_value = None

    with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
         patch.object(socket, "socket", return_value=fake_sock):
        result = probe.probe("example.com", 51820, timeout=0.01)

    assert result["verified"] is True
    assert result["response_type"] == "handshake_response"


def test_wireguard_probe_timeout_is_not_verified():
    probe = WireGuardProbe()
    fake_sock = MagicMock()
    fake_sock.recvfrom.side_effect = socket.timeout()
    fake_sock.sendto.return_value = None

    with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
         patch.object(socket, "socket", return_value=fake_sock):
        result = probe.probe("example.com", 51820, timeout=0.01)

    assert result["verified"] is False
    assert result["response_type"] == "timeout"

