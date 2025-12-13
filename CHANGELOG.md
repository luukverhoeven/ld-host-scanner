# Changelog

All notable changes to LD Host Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-12-13

### Added
- **Authenticated WireGuard probes** with full Noise_IKpsk2 handshake protocol
- **`WIREGUARD_SCANNER_PRIVATE_KEY`** config option for scanner identity
- Scanner can now be added as a WireGuard peer for reliable service verification
- WireGuard ports show "verified (handshake_response)" when server responds

### Changed
- WireGuard probe now implements proper cryptographic handshake (DH, ChaCha20-Poly1305 AEAD)
- Improved WireGuard detection reliability - no longer depends on firewall behavior
- Updated README with step-by-step WireGuard verification setup guide

### Technical
- Added `_dh()` method for X25519 Diffie-Hellman key exchange
- Added `_aead_encrypt()` method for ChaCha20-Poly1305 encryption
- Added Noise protocol helpers: `_blake2s_hash()`, `_blake2s_hmac()`, `_hkdf_blake2s()`
- Added `_tai64n_timestamp()` for WireGuard timestamp format
- Separated static and ephemeral keypairs in WireGuardProbe class

## [1.1.0] - 2025-12-13

### Added
- **Host Uptime Status graph** on dashboard showing online/offline history over time
- **Configurable host check interval** via `HOST_CHECK_INTERVAL_MINUTES` environment variable (default: 15)
- **HostStatusHistory model** for tracking historical host status checks
- **`/api/host-status-history` endpoint** for host uptime chart data
- **Version endpoint** at `/version` to check running version
- **CHANGELOG.md** for tracking release history

### Changed
- Health endpoint now includes version information
- Startup logs now display version number

## [1.0.0] - 2025-12-13

### Added
- Initial release of LD Host Scanner
- **Port scanning** with Rustscan (TCP) and nmap (UDP)
- **Real-time scan progress** with Server-Sent Events (SSE)
- **Dashboard** with live port discovery and scan status
- **Host online checks** every 15 minutes with ICMP/TCP fallback
- **Email notifications** via SMTP for port changes
- **Webhook notifications** for Discord/Slack
- **Expected ports monitoring** with alerts when ports go offline
- **WireGuard verification** with active probe support
- **Service detection** with nmap version scanning
- **Port history chart** showing open ports over time
- **Prometheus metrics** at `/metrics` endpoint
- **Docker support** with multi-stage build
- **SQLite database** for persistent storage
- **APScheduler** for job scheduling

### Security
- Input validation for target hostname (RFC 1123 compliant)
- Protection against shell injection in scan commands
- Capability-based permissions for network scanning
