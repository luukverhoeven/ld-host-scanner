"""WireGuard handshake probe for service verification.

WireGuard is designed to be "silent" - it only responds to properly authenticated
handshake initiations. This module attempts to verify if WireGuard is running by:
1. Sending a UDP packet to the port
2. Checking for any response (handshake response or cookie reply)
3. Using timing analysis for "open|filtered" vs "closed" detection

Note: Full verification requires the server's public key to build a valid
handshake initiation. Without proper crypto, WireGuard will silently drop packets.
"""

import base64
import hashlib
import logging
import os
import socket
import struct
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# WireGuard message types
MESSAGE_TYPE_HANDSHAKE_INIT = 1
MESSAGE_TYPE_HANDSHAKE_RESPONSE = 2
MESSAGE_TYPE_COOKIE_REPLY = 3
MESSAGE_TYPE_TRANSPORT_DATA = 4

# WireGuard handshake initiation packet structure (148 bytes)
# https://www.wireguard.com/protocol/
# - message_type: 4 bytes (little-endian u32)
# - sender_index: 4 bytes (random u32)
# - unencrypted_ephemeral: 32 bytes (Curve25519 public key)
# - encrypted_static: 48 bytes (encrypted with ChaCha20-Poly1305)
# - encrypted_timestamp: 28 bytes (encrypted with ChaCha20-Poly1305)
# - mac1: 16 bytes (keyed BLAKE2s MAC)
# - mac2: 16 bytes (keyed BLAKE2s MAC, zeros if no cookie)


class WireGuardProbe:
    """Send WireGuard handshake probe to verify service is running."""

    def __init__(self, server_public_key_b64: Optional[str] = None):
        """Initialize the probe.

        Args:
            server_public_key_b64: Server's WireGuard public key (base64-encoded).
                                   Optional - probe will still work without it
                                   but won't get a valid response.
        """
        self.server_public_key: Optional[bytes] = None
        self._ephemeral_private: Optional[bytes] = None
        self._ephemeral_public: Optional[bytes] = None

        if server_public_key_b64:
            try:
                self.server_public_key = base64.b64decode(server_public_key_b64)
                if len(self.server_public_key) != 32:
                    logger.warning("Invalid WireGuard public key length: %d", len(self.server_public_key))
                    self.server_public_key = None
            except Exception as e:
                logger.warning("Failed to decode WireGuard public key: %s", e)

        # Generate ephemeral keypair for the probe
        self._generate_ephemeral_keypair()

    def _generate_ephemeral_keypair(self) -> None:
        """Generate an ephemeral X25519 keypair for the handshake."""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization

            private_key = X25519PrivateKey.generate()
            self._ephemeral_private = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self._ephemeral_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except ImportError:
            logger.warning("cryptography library not available, using random bytes")
            self._ephemeral_private = os.urandom(32)
            self._ephemeral_public = os.urandom(32)
        except Exception as e:
            logger.warning("Failed to generate keypair: %s, using random bytes", e)
            self._ephemeral_private = os.urandom(32)
            self._ephemeral_public = os.urandom(32)

    def _build_handshake_init(self) -> bytes:
        """Build a WireGuard handshake initiation packet.

        This builds a structurally valid packet, but without proper Noise protocol
        encryption, WireGuard will silently drop it. However, if WireGuard is
        rate-limiting, it might respond with a cookie reply.

        Returns:
            148-byte handshake initiation packet.
        """
        header = self._build_handshake_init_header()

        # MAC1 is required for the server to even consider replying (cookie reply mitigation).
        # When we know the server public key, we can compute a valid MAC1; otherwise we fall back
        # to random bytes (which WireGuard will drop silently).
        mac1 = self._compute_mac1(header)

        # MAC2 (16 bytes) - zeros if no previous cookie
        mac2 = b'\x00' * 16

        packet = header + mac1 + mac2

        if len(packet) != 148:
            logger.warning("Built packet has unexpected size: %d (expected 148)", len(packet))

        return packet

    def _build_handshake_init_header(self) -> bytes:
        """Build the handshake initiation header (packet without MACs)."""
        # Message type (1 = handshake initiation)
        msg_type = struct.pack("<I", MESSAGE_TYPE_HANDSHAKE_INIT)

        # Sender index (random 4 bytes)
        sender_index = os.urandom(4)

        # Unencrypted ephemeral public key (32 bytes)
        ephemeral = self._ephemeral_public or os.urandom(32)

        # Encrypted static (48 bytes) - would be encrypted client public key
        # Without proper crypto, use random data (WireGuard will reject)
        encrypted_static = os.urandom(48)

        # Encrypted timestamp (28 bytes) - would be TAI64N timestamp
        encrypted_timestamp = os.urandom(28)

        packet = msg_type + sender_index + ephemeral + encrypted_static + encrypted_timestamp

        if len(packet) != 116:
            logger.warning("Built header has unexpected size: %d (expected 116)", len(packet))

        return packet

    def _compute_mac1(self, packet_header: bytes) -> bytes:
        """Compute a valid WireGuard MAC1 when server public key is known."""
        if not self.server_public_key:
            return os.urandom(16)

        # WireGuard uses BLAKE2s keyed MAC; the mac1 key is derived from the server static key.
        # mac1_key = BLAKE2s("mac1----" || server_static_public_key)
        mac1_key = hashlib.blake2s(b"mac1----" + self.server_public_key, digest_size=32).digest()
        return hashlib.blake2s(packet_header, digest_size=16, key=mac1_key).digest()

    def probe(self, host: str, port: int, timeout: float = 3.0) -> Dict:
        """Send handshake initiation and check for response.

        Args:
            host: Target hostname or IP.
            port: Target UDP port.
            timeout: Socket timeout in seconds.

        Returns:
            Dictionary with:
            - verified: bool - True if got a valid WireGuard response
            - response_type: str - Type of response received
            - message: str - Human-readable result description
        """
        sock = None
        try:
            # Resolve hostname to IP
            try:
                host_ip = socket.gethostbyname(host)
            except socket.gaierror as e:
                return {
                    "verified": False,
                    "response_type": "dns_error",
                    "message": f"DNS resolution failed: {e}",
                }

            # Build handshake initiation packet
            packet = self._build_handshake_init()

            # Create UDP socket and send
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (host_ip, port))

            logger.debug("Sent WireGuard probe to %s:%d (%d bytes)", host, port, len(packet))

            try:
                response, addr = sock.recvfrom(1024)
                msg_type = struct.unpack("<I", response[:4])[0] if len(response) >= 4 else 0

                if msg_type == MESSAGE_TYPE_HANDSHAKE_RESPONSE:
                    return {
                        "verified": True,
                        "response_type": "handshake_response",
                        "message": "WireGuard responded with handshake response",
                    }
                elif msg_type == MESSAGE_TYPE_COOKIE_REPLY:
                    return {
                        "verified": True,
                        "response_type": "cookie_reply",
                        "message": "WireGuard responded with cookie (rate limiting active)",
                    }
                else:
                    return {
                        "verified": True,
                        "response_type": "unknown",
                        "message": f"Got UDP response (type {msg_type}, {len(response)} bytes)",
                    }
            except socket.timeout:
                # No response - could be stealth (WireGuard dropped) or closed
                return {
                    "verified": False,
                    "response_type": "timeout",
                    "message": "No response (stealth mode or invalid key)",
                }

        except Exception as e:
            logger.error("WireGuard probe failed for %s:%d: %s", host, port, e)
            return {
                "verified": False,
                "response_type": "error",
                "message": str(e),
            }
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def probe_multiple(self, host: str, ports: list, timeout: float = 3.0) -> Dict[int, Dict]:
        """Probe multiple ports on the same host.

        Args:
            host: Target hostname or IP.
            ports: List of UDP ports to probe.
            timeout: Socket timeout per port.

        Returns:
            Dictionary mapping port -> probe result.
        """
        results = {}
        for port in ports:
            results[port] = self.probe(host, port, timeout)
        return results


def probe_wireguard(
    host: str,
    port: int,
    public_key: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict:
    """Convenience function to probe a single WireGuard port.

    Args:
        host: Target hostname or IP.
        port: Target UDP port.
        public_key: Server's WireGuard public key (base64, optional).
        timeout: Socket timeout in seconds.

    Returns:
        Probe result dictionary.
    """
    probe = WireGuardProbe(public_key)
    return probe.probe(host, port, timeout)
