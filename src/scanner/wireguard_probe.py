"""WireGuard handshake probe for service verification.

WireGuard is designed to be "silent" - it only responds to properly authenticated
handshake initiations. This module implements the Noise_IKpsk2 handshake protocol
to verify if WireGuard is running by:
1. Building a cryptographically valid handshake initiation
2. Sending it to the WireGuard port
3. Checking for handshake response or cookie reply

Requirements for server response:
- Server's public key (for MAC1 and DH)
- Scanner's private key added as a peer on the server
"""

import base64
import hashlib
import hmac
import logging
import os
import socket
import struct
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# WireGuard message types
MESSAGE_TYPE_HANDSHAKE_INIT = 1
MESSAGE_TYPE_HANDSHAKE_RESPONSE = 2
MESSAGE_TYPE_COOKIE_REPLY = 3
MESSAGE_TYPE_TRANSPORT_DATA = 4

# WireGuard Noise protocol constants
NOISE_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
NOISE_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
NOISE_LABEL_MAC1 = b"mac1----"
NOISE_LABEL_COOKIE = b"cookie--"

# WireGuard handshake initiation packet structure (148 bytes)
# https://www.wireguard.com/protocol/
# - message_type: 4 bytes (little-endian u32)
# - sender_index: 4 bytes (random u32)
# - unencrypted_ephemeral: 32 bytes (Curve25519 public key)
# - encrypted_static: 48 bytes (encrypted with ChaCha20-Poly1305)
# - encrypted_timestamp: 28 bytes (encrypted with ChaCha20-Poly1305)
# - mac1: 16 bytes (keyed BLAKE2s MAC)
# - mac2: 16 bytes (keyed BLAKE2s MAC, zeros if no cookie)


def _blake2s_hash(data: bytes) -> bytes:
    """BLAKE2s hash with 32-byte output."""
    return hashlib.blake2s(data, digest_size=32).digest()


def _blake2s_hmac(key: bytes, data: bytes) -> bytes:
    """BLAKE2s-based HMAC."""
    return hmac.new(key, data, lambda: hashlib.blake2s(digest_size=32)).digest()


def _hkdf_blake2s(key: bytes, data: bytes, num_outputs: int = 1) -> Tuple[bytes, ...]:
    """HKDF-style key derivation using BLAKE2s.

    WireGuard's KDF uses HMAC-BLAKE2s for key derivation.
    """
    # Extract
    prk = _blake2s_hmac(key, data)

    # Expand
    outputs = []
    t = b""
    for i in range(1, num_outputs + 1):
        t = _blake2s_hmac(prk, t + bytes([i]))
        outputs.append(t)

    return tuple(outputs)


def _tai64n_timestamp() -> bytes:
    """Generate TAI64N timestamp (12 bytes).

    TAI64N is seconds since 1970 + 2^62 (8 bytes) + nanoseconds (4 bytes).
    """
    now = time.time()
    secs = int(now) + (1 << 62)  # TAI64 offset
    nsecs = int((now % 1) * 1e9)
    return struct.pack(">QI", secs, nsecs)


class WireGuardProbe:
    """Send WireGuard handshake probe to verify service is running."""

    def __init__(
        self,
        server_public_key_b64: Optional[str] = None,
        scanner_private_key_b64: Optional[str] = None,
    ):
        """Initialize the probe.

        Args:
            server_public_key_b64: Server's WireGuard public key (base64-encoded).
                                   Required for MAC1 computation and DH.
            scanner_private_key_b64: Scanner's static private key (base64-encoded).
                                     If provided, the server can recognize the scanner
                                     as a known peer and respond to handshakes.
                                     If not provided, uses ephemeral keys (server won't respond).
        """
        self.server_public_key: Optional[bytes] = None
        self._static_private: Optional[bytes] = None
        self._static_public: Optional[bytes] = None
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

        # Load static scanner keypair if provided
        if scanner_private_key_b64:
            self._load_static_keypair(scanner_private_key_b64)
        else:
            # Generate random static key (server won't recognize us)
            self._generate_static_keypair()

        # Always generate fresh ephemeral keypair for each probe instance
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

    def _generate_static_keypair(self) -> None:
        """Generate a random static X25519 keypair (server won't recognize us)."""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

            private_key = X25519PrivateKey.generate()
            self._static_private = private_key.private_bytes_raw()
            self._static_public = private_key.public_key().public_bytes_raw()
        except ImportError:
            self._static_private = os.urandom(32)
            self._static_public = os.urandom(32)
        except Exception:
            self._static_private = os.urandom(32)
            self._static_public = os.urandom(32)

    def _load_static_keypair(self, private_key_b64: str) -> None:
        """Load a static X25519 keypair from base64-encoded private key.

        Using a static keypair allows the WireGuard server to recognize the scanner
        as a known peer and respond to handshake initiations.

        Args:
            private_key_b64: Base64-encoded X25519 private key (32 bytes).
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

            private_bytes = base64.b64decode(private_key_b64)
            if len(private_bytes) != 32:
                logger.warning("Invalid scanner private key length: %d, generating random", len(private_bytes))
                self._generate_static_keypair()
                return

            private_key = X25519PrivateKey.from_private_bytes(private_bytes)
            self._static_private = private_bytes
            self._static_public = private_key.public_key().public_bytes_raw()
            logger.debug("Loaded static scanner keypair for WireGuard probe")
        except ImportError:
            logger.warning("cryptography library not available, generating random static keypair")
            self._generate_static_keypair()
        except Exception as e:
            logger.warning("Failed to load static keypair: %s, generating random", e)
            self._generate_static_keypair()

    def _dh(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform X25519 Diffie-Hellman exchange."""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
                X25519PublicKey,
            )

            priv = X25519PrivateKey.from_private_bytes(private_key)
            pub = X25519PublicKey.from_public_bytes(public_key)
            return priv.exchange(pub)
        except Exception as e:
            logger.warning("DH exchange failed: %s", e)
            return os.urandom(32)

    def _aead_encrypt(self, key: bytes, nonce: int, plaintext: bytes, aad: bytes) -> bytes:
        """ChaCha20-Poly1305 AEAD encryption."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            # WireGuard uses 8-byte little-endian nonce padded to 12 bytes
            nonce_bytes = struct.pack("<Q", nonce) + b"\x00\x00\x00\x00"
            cipher = ChaCha20Poly1305(key)
            return cipher.encrypt(nonce_bytes, plaintext, aad)
        except Exception as e:
            logger.warning("AEAD encryption failed: %s", e)
            # Return random bytes of correct length (plaintext + 16-byte tag)
            return os.urandom(len(plaintext) + 16)

    def _build_handshake_init(self) -> bytes:
        """Build a WireGuard handshake initiation packet.

        Implements the Noise_IKpsk2 handshake protocol for proper authentication.
        The server will only respond if it recognizes our static public key as a peer.

        Returns:
            148-byte handshake initiation packet.
        """
        header = self._build_handshake_init_header()

        # MAC1 is required for the server to even consider replying
        mac1 = self._compute_mac1(header)

        # MAC2 (16 bytes) - zeros if no previous cookie
        mac2 = b'\x00' * 16

        packet = header + mac1 + mac2

        if len(packet) != 148:
            logger.warning("Built packet has unexpected size: %d (expected 148)", len(packet))

        return packet

    def _build_handshake_init_header(self) -> bytes:
        """Build the handshake initiation header using Noise_IKpsk2 protocol.

        Implements the initiator side of WireGuard's Noise handshake:
        1. Initialize chaining key (C) and hash (H)
        2. Mix in responder's static public key
        3. DH(ephemeral, responder_static), encrypt initiator's static key
        4. DH(initiator_static, responder_static), encrypt timestamp
        """
        if not self.server_public_key:
            # Without server public key, we can't do proper crypto
            return self._build_handshake_init_header_fallback()

        # Initialize Noise state
        # C = HASH(CONSTRUCTION)
        c = _blake2s_hash(NOISE_CONSTRUCTION)
        # H = HASH(C || IDENTIFIER)
        h = _blake2s_hash(c + NOISE_IDENTIFIER)
        # H = HASH(H || responder_static_public)
        h = _blake2s_hash(h + self.server_public_key)

        # Message type and sender index
        msg_type = struct.pack("<I", MESSAGE_TYPE_HANDSHAKE_INIT)
        sender_index = os.urandom(4)

        # Ephemeral public key (unencrypted)
        ephemeral_pub = self._ephemeral_public

        # Mix ephemeral into chaining key: C = KDF1(C, ephemeral_pub)
        (c,) = _hkdf_blake2s(c, ephemeral_pub, 1)
        # Mix ephemeral into hash: H = HASH(H || ephemeral_pub)
        h = _blake2s_hash(h + ephemeral_pub)

        # DH(ephemeral_private, responder_static_public)
        dh_result = self._dh(self._ephemeral_private, self.server_public_key)
        # Derive encryption key: (C, k) = KDF2(C, dh_result)
        c, k = _hkdf_blake2s(c, dh_result, 2)

        # Encrypt initiator's static public key: AEAD(k, 0, static_pub, H)
        encrypted_static = self._aead_encrypt(k, 0, self._static_public, h)
        # Mix into hash: H = HASH(H || encrypted_static)
        h = _blake2s_hash(h + encrypted_static)

        # DH(initiator_static_private, responder_static_public)
        dh_result2 = self._dh(self._static_private, self.server_public_key)
        # Derive encryption key: (C, k) = KDF2(C, dh_result2)
        c, k = _hkdf_blake2s(c, dh_result2, 2)

        # Encrypt timestamp: AEAD(k, 0, timestamp, H)
        timestamp = _tai64n_timestamp()
        encrypted_timestamp = self._aead_encrypt(k, 0, timestamp, h)

        # Build packet
        packet = msg_type + sender_index + ephemeral_pub + encrypted_static + encrypted_timestamp

        if len(packet) != 116:
            logger.warning("Built header has unexpected size: %d (expected 116)", len(packet))

        return packet

    def _build_handshake_init_header_fallback(self) -> bytes:
        """Build handshake header with random data (no server key available)."""
        msg_type = struct.pack("<I", MESSAGE_TYPE_HANDSHAKE_INIT)
        sender_index = os.urandom(4)
        ephemeral = self._ephemeral_public or os.urandom(32)
        encrypted_static = os.urandom(48)
        encrypted_timestamp = os.urandom(28)
        return msg_type + sender_index + ephemeral + encrypted_static + encrypted_timestamp

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
    scanner_private_key: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict:
    """Convenience function to probe a single WireGuard port.

    Args:
        host: Target hostname or IP.
        port: Target UDP port.
        public_key: Server's WireGuard public key (base64, optional).
        scanner_private_key: Scanner's static private key (base64, optional).
                            If provided, the server can recognize the scanner
                            as a known peer and respond to handshakes.
        timeout: Socket timeout in seconds.

    Returns:
        Probe result dictionary.
    """
    probe = WireGuardProbe(public_key, scanner_private_key)
    return probe.probe(host, port, timeout)
