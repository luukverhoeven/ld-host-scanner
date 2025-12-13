"""Common port service database for enriching scan results."""

from typing import Dict, Optional

# Common ports database: (port, protocol) -> service info
# Based on IANA port assignments and common usage patterns
COMMON_PORTS: Dict[tuple, Dict[str, str]] = {
    # FTP
    (20, "tcp"): {"service": "ftp-data", "description": "FTP Data Transfer"},
    (21, "tcp"): {"service": "ftp", "description": "FTP Control"},

    # SSH, Telnet
    (22, "tcp"): {"service": "ssh", "description": "Secure Shell"},
    (23, "tcp"): {"service": "telnet", "description": "Telnet"},

    # SMTP
    (25, "tcp"): {"service": "smtp", "description": "Simple Mail Transfer"},
    (465, "tcp"): {"service": "smtps", "description": "SMTP over SSL"},
    (587, "tcp"): {"service": "submission", "description": "SMTP Submission"},

    # DNS
    (53, "tcp"): {"service": "dns", "description": "Domain Name System"},
    (53, "udp"): {"service": "dns", "description": "Domain Name System"},

    # DHCP
    (67, "udp"): {"service": "dhcp", "description": "DHCP Server"},
    (68, "udp"): {"service": "dhcp", "description": "DHCP Client"},

    # TFTP
    (69, "udp"): {"service": "tftp", "description": "Trivial File Transfer"},

    # HTTP/HTTPS
    (80, "tcp"): {"service": "http", "description": "HTTP Web Server"},
    (443, "tcp"): {"service": "https", "description": "HTTPS Secure Web"},
    (8080, "tcp"): {"service": "http-alt", "description": "HTTP Alternate"},
    (8443, "tcp"): {"service": "https-alt", "description": "HTTPS Alternate"},
    (8000, "tcp"): {"service": "http-alt", "description": "HTTP Alternate"},
    (8888, "tcp"): {"service": "http-alt", "description": "HTTP Alternate"},

    # POP3
    (110, "tcp"): {"service": "pop3", "description": "Post Office Protocol v3"},
    (995, "tcp"): {"service": "pop3s", "description": "POP3 over SSL"},

    # IMAP
    (143, "tcp"): {"service": "imap", "description": "Internet Message Access"},
    (993, "tcp"): {"service": "imaps", "description": "IMAP over SSL"},

    # NetBIOS
    (137, "udp"): {"service": "netbios-ns", "description": "NetBIOS Name Service"},
    (138, "udp"): {"service": "netbios-dgm", "description": "NetBIOS Datagram"},
    (139, "tcp"): {"service": "netbios-ssn", "description": "NetBIOS Session"},

    # SNMP
    (161, "udp"): {"service": "snmp", "description": "Simple Network Management"},
    (162, "udp"): {"service": "snmptrap", "description": "SNMP Trap"},

    # LDAP
    (389, "tcp"): {"service": "ldap", "description": "LDAP Directory"},
    (636, "tcp"): {"service": "ldaps", "description": "LDAP over SSL"},

    # SMB/CIFS
    (445, "tcp"): {"service": "smb", "description": "SMB/CIFS File Sharing"},

    # Kerberos
    (88, "tcp"): {"service": "kerberos", "description": "Kerberos Authentication"},
    (88, "udp"): {"service": "kerberos", "description": "Kerberos Authentication"},

    # NTP
    (123, "udp"): {"service": "ntp", "description": "Network Time Protocol"},

    # HTTPS proxy
    (3128, "tcp"): {"service": "squid", "description": "Squid Proxy"},

    # MySQL
    (3306, "tcp"): {"service": "mysql", "description": "MySQL Database"},

    # PostgreSQL
    (5432, "tcp"): {"service": "postgresql", "description": "PostgreSQL Database"},

    # Microsoft SQL Server
    (1433, "tcp"): {"service": "mssql", "description": "Microsoft SQL Server"},
    (1434, "udp"): {"service": "mssql-m", "description": "MS SQL Monitor"},

    # Oracle
    (1521, "tcp"): {"service": "oracle", "description": "Oracle Database"},

    # MongoDB
    (27017, "tcp"): {"service": "mongodb", "description": "MongoDB Database"},
    (27018, "tcp"): {"service": "mongodb", "description": "MongoDB Shard"},
    (27019, "tcp"): {"service": "mongodb", "description": "MongoDB Config"},

    # Redis
    (6379, "tcp"): {"service": "redis", "description": "Redis Database"},

    # Memcached
    (11211, "tcp"): {"service": "memcached", "description": "Memcached"},
    (11211, "udp"): {"service": "memcached", "description": "Memcached"},

    # Elasticsearch
    (9200, "tcp"): {"service": "elasticsearch", "description": "Elasticsearch HTTP"},
    (9300, "tcp"): {"service": "elasticsearch", "description": "Elasticsearch Transport"},

    # RDP
    (3389, "tcp"): {"service": "rdp", "description": "Remote Desktop Protocol"},
    (3389, "udp"): {"service": "rdp", "description": "Remote Desktop Protocol"},

    # VNC
    (5900, "tcp"): {"service": "vnc", "description": "VNC Remote Desktop"},
    (5901, "tcp"): {"service": "vnc", "description": "VNC Display 1"},
    (5902, "tcp"): {"service": "vnc", "description": "VNC Display 2"},
    (5903, "tcp"): {"service": "vnc", "description": "VNC Display 3"},

    # X11
    (6000, "tcp"): {"service": "x11", "description": "X Window System"},

    # Syslog
    (514, "udp"): {"service": "syslog", "description": "Syslog"},

    # Docker
    (2375, "tcp"): {"service": "docker", "description": "Docker API (unencrypted)"},
    (2376, "tcp"): {"service": "docker", "description": "Docker API (TLS)"},

    # Kubernetes
    (6443, "tcp"): {"service": "kubernetes", "description": "Kubernetes API"},
    (10250, "tcp"): {"service": "kubelet", "description": "Kubernetes Kubelet"},

    # SSH alternatives
    (2222, "tcp"): {"service": "ssh-alt", "description": "SSH Alternate"},

    # Git
    (9418, "tcp"): {"service": "git", "description": "Git Protocol"},

    # Prometheus
    (9090, "tcp"): {"service": "prometheus", "description": "Prometheus"},
    (9091, "tcp"): {"service": "prometheus-push", "description": "Prometheus Pushgateway"},
    (9093, "tcp"): {"service": "alertmanager", "description": "Prometheus Alertmanager"},

    # Grafana
    (3000, "tcp"): {"service": "grafana", "description": "Grafana Dashboard"},

    # Node.js / Development
    (3001, "tcp"): {"service": "nodejs", "description": "Node.js Development"},
    (4200, "tcp"): {"service": "angular", "description": "Angular CLI"},
    (5000, "tcp"): {"service": "flask", "description": "Flask/Python Dev"},
    (5173, "tcp"): {"service": "vite", "description": "Vite Dev Server"},
    (8081, "tcp"): {"service": "http-alt", "description": "HTTP Alternate"},

    # VPN
    (1194, "tcp"): {"service": "openvpn", "description": "OpenVPN"},
    (1194, "udp"): {"service": "openvpn", "description": "OpenVPN"},
    (51820, "udp"): {"service": "wireguard", "description": "WireGuard VPN"},
    (500, "udp"): {"service": "isakmp", "description": "IPsec IKE"},
    (4500, "udp"): {"service": "ipsec-nat", "description": "IPsec NAT-T"},
    (1701, "udp"): {"service": "l2tp", "description": "L2TP VPN"},

    # Proxy/Reverse Proxy
    (8001, "tcp"): {"service": "proxy", "description": "HTTP Proxy"},
    (8002, "tcp"): {"service": "proxy", "description": "HTTP Proxy"},

    # RabbitMQ
    (5672, "tcp"): {"service": "amqp", "description": "RabbitMQ AMQP"},
    (15672, "tcp"): {"service": "rabbitmq", "description": "RabbitMQ Management"},

    # ZooKeeper
    (2181, "tcp"): {"service": "zookeeper", "description": "Apache ZooKeeper"},

    # Kafka
    (9092, "tcp"): {"service": "kafka", "description": "Apache Kafka"},

    # Jenkins
    (8180, "tcp"): {"service": "jenkins", "description": "Jenkins CI"},
    (50000, "tcp"): {"service": "jenkins-agent", "description": "Jenkins Agent"},

    # Minecraft
    (25565, "tcp"): {"service": "minecraft", "description": "Minecraft Server"},

    # Game servers
    (27015, "udp"): {"service": "srcds", "description": "Source Game Server"},
    (7777, "udp"): {"service": "unreal", "description": "Unreal Engine"},

    # RTSP
    (554, "tcp"): {"service": "rtsp", "description": "Real Time Streaming"},

    # SIP
    (5060, "tcp"): {"service": "sip", "description": "SIP VoIP"},
    (5060, "udp"): {"service": "sip", "description": "SIP VoIP"},
    (5061, "tcp"): {"service": "sips", "description": "SIP over TLS"},

    # Apple services
    (548, "tcp"): {"service": "afp", "description": "Apple Filing Protocol"},
    (5353, "udp"): {"service": "mdns", "description": "Multicast DNS (Bonjour)"},

    # Printing
    (631, "tcp"): {"service": "ipp", "description": "Internet Printing"},
    (9100, "tcp"): {"service": "jetdirect", "description": "HP JetDirect"},

    # Telemetry/Monitoring
    (8125, "udp"): {"service": "statsd", "description": "StatsD"},
    (4317, "tcp"): {"service": "otlp", "description": "OpenTelemetry"},

    # Consul
    (8500, "tcp"): {"service": "consul", "description": "HashiCorp Consul"},
    (8600, "udp"): {"service": "consul-dns", "description": "Consul DNS"},

    # Vault
    (8200, "tcp"): {"service": "vault", "description": "HashiCorp Vault"},

    # NATS
    (4222, "tcp"): {"service": "nats", "description": "NATS Messaging"},

    # etcd
    (2379, "tcp"): {"service": "etcd", "description": "etcd Client"},
    (2380, "tcp"): {"service": "etcd", "description": "etcd Peer"},

    # InfluxDB
    (8086, "tcp"): {"service": "influxdb", "description": "InfluxDB HTTP"},

    # CouchDB
    (5984, "tcp"): {"service": "couchdb", "description": "CouchDB"},

    # Neo4j
    (7474, "tcp"): {"service": "neo4j", "description": "Neo4j HTTP"},
    (7687, "tcp"): {"service": "neo4j-bolt", "description": "Neo4j Bolt"},

    # Cassandra
    (9042, "tcp"): {"service": "cassandra", "description": "Cassandra CQL"},
    (7000, "tcp"): {"service": "cassandra", "description": "Cassandra Cluster"},

    # ClickHouse
    (8123, "tcp"): {"service": "clickhouse", "description": "ClickHouse HTTP"},
    (9000, "tcp"): {"service": "clickhouse", "description": "ClickHouse Native"},

    # MinIO
    (9001, "tcp"): {"service": "minio", "description": "MinIO Console"},

    # Home automation
    (1883, "tcp"): {"service": "mqtt", "description": "MQTT Broker"},
    (8883, "tcp"): {"service": "mqtts", "description": "MQTT over TLS"},
    (8123, "tcp"): {"service": "homeassistant", "description": "Home Assistant"},

    # Plex
    (32400, "tcp"): {"service": "plex", "description": "Plex Media Server"},
}


def get_common_service(port: int, protocol: str = "tcp") -> Optional[Dict[str, str]]:
    """Get common service info for a port.

    Args:
        port: Port number (1-65535).
        protocol: Protocol ('tcp' or 'udp').

    Returns:
        Dictionary with 'service' and 'description' keys, or None if not found.
    """
    return COMMON_PORTS.get((port, protocol.lower()))


def get_common_service_name(port: int, protocol: str = "tcp") -> Optional[str]:
    """Get just the common service name for a port.

    Args:
        port: Port number (1-65535).
        protocol: Protocol ('tcp' or 'udp').

    Returns:
        Service name string, or None if not found.
    """
    info = get_common_service(port, protocol)
    return info["service"] if info else None


def enrich_port_with_common_service(port_data: dict) -> dict:
    """Enrich a port data dictionary with common service info.

    Args:
        port_data: Dictionary with 'port' and 'protocol' keys.

    Returns:
        Same dictionary with 'common_service' key added.
    """
    port_num = port_data.get("port")
    protocol = port_data.get("protocol", "tcp")

    common = get_common_service_name(port_num, protocol)
    port_data["common_service"] = common

    return port_data


def enrich_ports_list(ports: list) -> list:
    """Enrich a list of port data dictionaries with common service info.

    Args:
        ports: List of port dictionaries.

    Returns:
        Same list with 'common_service' added to each port.
    """
    return [enrich_port_with_common_service(port) for port in ports]


def format_service_display(
    detected_service: Optional[str],
    port: int,
    protocol: str = "tcp",
) -> str:
    """Format service information for display.

    Shows both detected service and common service:
    - 'nginx/1.20.1 (http)' - detected with common
    - 'unknown (http)' - unknown detected but known common
    - 'custom-app' - detected but no common mapping
    - 'unknown' - nothing known

    Args:
        detected_service: Service name from scan (may be 'unknown' or None).
        port: Port number.
        protocol: Protocol ('tcp' or 'udp').

    Returns:
        Formatted string for display.
    """
    common = get_common_service_name(port, protocol)
    detected = detected_service or "unknown"

    if common:
        if detected == common:
            # Same service, no need to repeat
            return detected
        else:
            # Show both: detected (common)
            return f"{detected} ({common})"
    else:
        return detected
