# LD Host Scanner

A Docker-based network security scanner that monitors your home network for open ports and online status. Runs automated scans every 2 hours and sends alerts via email and webhooks (Discord/Slack).

## Features

- **Full spectrum port scanning**: TCP (1-65535) and UDP (top 1000 ports)
- **Online/offline detection**: Quick checks every 15 minutes
- **Automated scheduling**: Configurable scan intervals (default: 2 hours)
- **Expected ports monitoring**: Alert when critical services go down
- **Stealth service detection**: Track services like WireGuard that don't respond to probes
- **WireGuard verification**: Optional handshake probe to verify VPN is running
- **Email notifications**: SMTP alerts with HTML reports
- **Webhook notifications**: Discord and Slack compatible
- **Web dashboard**: Real-time status and scan history
- **REST API**: Programmatic access to scan data
- **Docker deployment**: Easy setup with docker-compose

## Quick Start

### 1. Clone and configure

```bash
# Clone the repository
git clone <repository-url>
cd ld-host-scanner

# Copy example environment file
cp .env.example .env

# Edit configuration
nano .env
```

### 2. Configure notifications (optional)

Edit `.env` to add your notification settings:

```bash
# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=LD Host Scanner <your-email@gmail.com>
SMTP_TO=alerts@example.com

# Discord webhook
WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy

# Or Slack webhook
WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
```

### 3. Build and run

```bash
# Build and start the container
docker-compose build && docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### 4. Access the dashboard

Open your browser to: **http://localhost:8080**

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_HOST` | `example.com` | Host to scan (must be configured) |
| `SCAN_INTERVAL_HOURS` | `2` | Full scan frequency |
| `SMTP_HOST` | - | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USER` | - | SMTP username |
| `SMTP_PASSWORD` | - | SMTP password |
| `SMTP_FROM` | - | Email sender address |
| `SMTP_TO` | - | Email recipient address |
| `WEBHOOK_URL` | - | Discord/Slack webhook URL |
| `TZ` | `Europe/Amsterdam` | Timezone |
| `LOG_LEVEL` | `INFO` | Logging level |
| `TCP_SERVICE_ENRICHMENT` | `true` | Run targeted TCP `nmap -sV` on Rustscan hits |
| `TCP_SERVICE_ENRICHMENT_INTENSITY` | `light` | TCP version detection intensity (`light|normal|thorough`) |
| `TCP_SERVICE_ENRICHMENT_PORTS_LIMIT` | `200` | Max TCP ports to version-scan per run |
| `UDP_TOP_PORTS` | `1000` | UDP `nmap --top-ports` count when no range is set |
| `UDP_VERSION_DETECTION` | `true` | Run UDP version detection on prioritized ports |
| `UDP_VERSION_DETECTION_INTENSITY` | `light` | UDP version detection intensity (`light|normal|thorough`) |
| `UDP_VERSION_DETECTION_PORTS_LIMIT` | `50` | Max UDP ports to version-scan per run |
| `EXPECTED_PORTS` | - | Ports that should be open (e.g., `80/tcp,443/tcp,448/udp`) |
| `WIREGUARD_PUBLIC_KEY` | - | WireGuard server public key (base64) for probe verification |
| `WIREGUARD_PROBE_PORTS` | - | Ports to probe for WireGuard (default: 448, 51820) |

### Scan Intervals

- **Full scan**: Every 2 hours (configurable via `SCAN_INTERVAL_HOURS`)
- **Host check**: Every 15 minutes (quick online/offline check)
- **Initial scan**: Runs immediately on container startup

### Expected Ports Monitoring

Monitor critical services and get alerts when they go down:

```bash
# In .env
EXPECTED_PORTS=80/tcp,443/tcp,22/tcp,448/udp
```

Features:
- **UDP ports are explicitly scanned** even if not in nmap's top-N (e.g., port 448)
- **Alerts only on state change** - notifies when a port goes from open to closed
- **Dashboard shows status** - expected ports card with open/missing indicators

### Stealth Services & WireGuard

Some services like WireGuard are designed to be "silent" - they don't respond to port scans. The scanner handles these with special detection:

**Stealth Detection:**
- Ports that return "open|filtered" AND are in your expected list are marked as "stealth"
- Dashboard shows a yellow "stealth" badge with tooltip
- This means: "We expect this service to be running, but can't verify it"

**WireGuard Verification (Optional):**

If you want to actively verify WireGuard is running, provide the server's public key:

```bash
# In .env
EXPECTED_PORTS=448/udp
WIREGUARD_PUBLIC_KEY=<your-wireguard-server-public-key-base64>
```

The scanner will send a WireGuard handshake probe. If WireGuard responds (even with a rate-limit cookie), it's marked as "verified" instead of "stealth".

**Note:** WireGuard only responds to properly encrypted handshakes. Without the public key, the scanner can only detect "no ICMP rejection" which indicates something is listening but can't confirm it's WireGuard.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/history` | GET | Scan history |
| `/health` | GET | Health check |
| `/api/status` | GET | Current target status |
| `/api/scans` | GET | List recent scans |
| `/api/scans/{id}` | GET | Get scan details |
| `/api/scans/trigger` | POST | Trigger manual scan |
| `/api/changes` | GET | Port change history |
| `/api/jobs` | GET | Scheduled jobs info |
| `/docs` | GET | API documentation (Swagger) |

### Manual Scan Trigger

```bash
curl -X POST http://localhost:8080/api/scans/trigger
```

### Get Current Status

```bash
curl http://localhost:8080/api/status
```

## Docker Capabilities

The container requires specific Linux capabilities for nmap to function:

- `NET_RAW`: TCP SYN scans, ICMP ping
- `NET_ADMIN`: OS detection, advanced scans

These are configured in `docker-compose.yml`.

## Testing

Tests run inside Docker to ensure the correct environment with all dependencies:

```bash
# Run all tests
docker-compose run --rm --no-deps -v "$(pwd)/tests:/app/tests" ld-host-scanner \
  sh -c "pip install -q pytest pytest-asyncio && python -m pytest tests/ -v"

# Run with coverage
docker-compose run --rm --no-deps -v "$(pwd)/tests:/app/tests" ld-host-scanner \
  sh -c "pip install -q pytest pytest-asyncio pytest-cov && python -m pytest tests/ --cov=src --cov-report=term-missing"

# Run a single test file
docker-compose run --rm --no-deps -v "$(pwd)/tests:/app/tests" ld-host-scanner \
  sh -c "pip install -q pytest pytest-asyncio && python -m pytest tests/test_port_scanner.py -v"
```

## Project Structure

```
ld-host-scanner/
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── src/
│   ├── main.py              # Entry point
│   ├── config.py            # Configuration
│   ├── scanner/             # Port scanning logic
│   ├── storage/             # Database layer
│   ├── notifications/       # Email & webhook alerts
│   ├── scheduler/           # Job scheduling
│   └── web/                 # FastAPI dashboard
├── tests/                   # Test suite (pytest)
├── data/                    # Persistent data (SQLite)
├── requirements.txt
├── .env.example
└── README.md
```

## Notifications

### Email Alerts

HTML-formatted emails include:
- Host status (online/offline)
- List of open ports with service detection
- Port changes (newly opened/closed)

### Webhook Alerts (Discord/Slack)

Rich embeds showing:
- Host status
- Open port count
- Port changes with color coding (red = opened, green = closed)
- Port details with service names

## Troubleshooting

### Container won't start

Check logs:
```bash
docker-compose logs ld-host-scanner
```

### Scans not running

Verify the scheduler is running:
```bash
curl http://localhost:8080/api/jobs
```

### Email not sending

1. Check SMTP settings in `.env`
2. For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833)
3. Check logs for SMTP errors

### Permission denied errors

Ensure the container has proper capabilities:
```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

## Security Notes

- Container runs as non-root user with limited capabilities
- Credentials stored in environment variables (not in code)
- SQLite database persisted in mounted volume
- No scanning of private/internal networks by default

## License

MIT
