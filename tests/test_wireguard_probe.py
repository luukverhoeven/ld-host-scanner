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


def test_wireguard_probe_unknown_response_type():
    """Test handling of unknown WireGuard message type."""
    probe = WireGuardProbe()

    fake_sock = MagicMock()
    # Message type 99 is not a known WireGuard type
    fake_sock.recvfrom.return_value = (struct.pack("<I", 99) + b"x" * 20, ("1.2.3.4", 51820))
    fake_sock.sendto.return_value = None

    with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
         patch.object(socket, "socket", return_value=fake_sock):
        result = probe.probe("example.com", 51820, timeout=0.01)

    assert result["verified"] is True
    assert result["response_type"] == "unknown"
    assert "type 99" in result["message"]


def test_wireguard_probe_short_response():
    """Test handling of response shorter than 4 bytes."""
    probe = WireGuardProbe()

    fake_sock = MagicMock()
    # Response too short to contain message type
    fake_sock.recvfrom.return_value = (b"ab", ("1.2.3.4", 51820))
    fake_sock.sendto.return_value = None

    with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
         patch.object(socket, "socket", return_value=fake_sock):
        result = probe.probe("example.com", 51820, timeout=0.01)

    assert result["verified"] is True
    assert result["response_type"] == "unknown"


def test_wireguard_probe_general_exception():
    """Test handling of unexpected exceptions during probe."""
    probe = WireGuardProbe()

    with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
         patch.object(socket, "socket", side_effect=OSError("Network unreachable")):
        result = probe.probe("example.com", 51820, timeout=0.01)

    assert result["verified"] is False
    assert result["response_type"] == "error"
    assert "Network unreachable" in result["message"]


class TestWireGuardProbeInit:
    """Tests for WireGuardProbe initialization."""

    def test_init_with_valid_public_key(self):
        """Test initialization with valid base64 public key."""
        valid_key = base64.b64encode(b"\x01" * 32).decode("ascii")
        probe = WireGuardProbe(server_public_key_b64=valid_key)
        assert probe.server_public_key == b"\x01" * 32

    def test_init_with_invalid_length_key(self):
        """Test initialization with wrong-length public key."""
        # 16 bytes instead of 32
        short_key = base64.b64encode(b"\x01" * 16).decode("ascii")
        probe = WireGuardProbe(server_public_key_b64=short_key)
        assert probe.server_public_key is None

    def test_init_with_invalid_base64(self):
        """Test initialization with invalid base64 string."""
        probe = WireGuardProbe(server_public_key_b64="not-valid-base64!!!")
        assert probe.server_public_key is None

    def test_init_without_public_key(self):
        """Test initialization without public key."""
        probe = WireGuardProbe()
        assert probe.server_public_key is None
        # Should still have ephemeral keys
        assert probe._ephemeral_public is not None
        assert len(probe._ephemeral_public) == 32

    def test_init_generates_ephemeral_keypair(self):
        """Test that ephemeral keypair is generated."""
        probe = WireGuardProbe()
        assert probe._ephemeral_private is not None
        assert probe._ephemeral_public is not None
        assert len(probe._ephemeral_private) == 32
        assert len(probe._ephemeral_public) == 32


class TestProbeMultiple:
    """Tests for probe_multiple method."""

    def test_probe_multiple_ports(self):
        """Test probing multiple ports."""
        probe = WireGuardProbe()
        fake_sock = MagicMock()
        fake_sock.recvfrom.side_effect = socket.timeout()
        fake_sock.sendto.return_value = None

        with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
             patch.object(socket, "socket", return_value=fake_sock):
            results = probe.probe_multiple("example.com", [51820, 51821, 51822], timeout=0.01)

        assert len(results) == 3
        assert 51820 in results
        assert 51821 in results
        assert 51822 in results
        for port, result in results.items():
            assert result["response_type"] == "timeout"

    def test_probe_multiple_empty_list(self):
        """Test probing with empty port list."""
        probe = WireGuardProbe()
        results = probe.probe_multiple("example.com", [], timeout=0.01)
        assert results == {}

    def test_probe_multiple_mixed_results(self):
        """Test probing multiple ports with different results."""
        probe = WireGuardProbe()

        call_count = [0]

        def mock_recvfrom(size):
            call_count[0] += 1
            if call_count[0] == 1:
                # First port - cookie reply
                return (struct.pack("<I", MESSAGE_TYPE_COOKIE_REPLY) + b"x" * 20, ("1.2.3.4", 51820))
            elif call_count[0] == 2:
                # Second port - timeout
                raise socket.timeout()
            else:
                # Third port - handshake response
                return (struct.pack("<I", MESSAGE_TYPE_HANDSHAKE_RESPONSE) + b"x" * 20, ("1.2.3.4", 51822))

        fake_sock = MagicMock()
        fake_sock.recvfrom.side_effect = mock_recvfrom
        fake_sock.sendto.return_value = None

        with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
             patch.object(socket, "socket", return_value=fake_sock):
            results = probe.probe_multiple("example.com", [51820, 51821, 51822], timeout=0.01)

        assert results[51820]["verified"] is True
        assert results[51820]["response_type"] == "cookie_reply"
        assert results[51821]["verified"] is False
        assert results[51821]["response_type"] == "timeout"
        assert results[51822]["verified"] is True
        assert results[51822]["response_type"] == "handshake_response"


class TestProbeWireguardConvenience:
    """Tests for probe_wireguard convenience function."""

    def test_probe_wireguard_without_key(self):
        """Test convenience function without public key."""
        from src.scanner.wireguard_probe import probe_wireguard

        fake_sock = MagicMock()
        fake_sock.recvfrom.side_effect = socket.timeout()
        fake_sock.sendto.return_value = None

        with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
             patch.object(socket, "socket", return_value=fake_sock):
            result = probe_wireguard("example.com", 51820, timeout=0.01)

        assert result["verified"] is False
        assert result["response_type"] == "timeout"

    def test_probe_wireguard_with_key(self):
        """Test convenience function with public key."""
        from src.scanner.wireguard_probe import probe_wireguard

        valid_key = base64.b64encode(b"\x02" * 32).decode("ascii")
        fake_sock = MagicMock()
        fake_sock.recvfrom.return_value = (struct.pack("<I", MESSAGE_TYPE_COOKIE_REPLY) + b"x" * 20, ("1.2.3.4", 51820))
        fake_sock.sendto.return_value = None

        with patch.object(socket, "gethostbyname", return_value="1.2.3.4"), \
             patch.object(socket, "socket", return_value=fake_sock):
            result = probe_wireguard("example.com", 51820, public_key=valid_key, timeout=0.01)

        assert result["verified"] is True
        assert result["response_type"] == "cookie_reply"


class TestMac1Computation:
    """Tests for MAC1 computation."""

    def test_mac1_without_server_key_returns_random(self):
        """Test MAC1 returns random bytes when no server key."""
        probe = WireGuardProbe(server_public_key_b64=None)
        header = probe._build_handshake_init_header()

        mac1_a = probe._compute_mac1(header)
        mac1_b = probe._compute_mac1(header)

        # Without server key, each call returns random bytes
        assert len(mac1_a) == 16
        assert len(mac1_b) == 16
        # Very unlikely to be equal if truly random
        assert mac1_a != mac1_b

    def test_mac1_with_server_key_is_deterministic(self):
        """Test MAC1 is deterministic with server key."""
        valid_key = base64.b64encode(b"\x03" * 32).decode("ascii")
        probe = WireGuardProbe(server_public_key_b64=valid_key)
        header = probe._build_handshake_init_header()

        mac1_a = probe._compute_mac1(header)
        mac1_b = probe._compute_mac1(header)

        assert mac1_a == mac1_b
        assert len(mac1_a) == 16


class TestKeyPairGeneration:
    """Tests for ephemeral keypair generation fallback."""

    def test_keypair_fallback_without_cryptography(self):
        """Test fallback to random bytes when cryptography unavailable."""
        with patch.dict("sys.modules", {"cryptography": None}):
            # Force reimport error
            probe = WireGuardProbe()
            # Should still have keys (random fallback)
            assert probe._ephemeral_private is not None
            assert probe._ephemeral_public is not None
            assert len(probe._ephemeral_private) == 32
            assert len(probe._ephemeral_public) == 32

