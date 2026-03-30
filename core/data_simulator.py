"""
CyberShield Ultimate - Data Simulator
Generates synthetic network traffic, threat map data, and security logs.
"""

import random
import time
import numpy as np
from datetime import datetime, timedelta


ATTACK_TYPES = ['Normal', 'DDoS', 'SQL Injection', 'Port Scan', 'Brute Force']
PROTOCOLS = ['TCP', 'UDP', 'ICMP']
SERVICES = ['http', 'https', 'ftp', 'ssh', 'dns', 'smtp', 'telnet', 'pop3']
FLAGS = ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'S2', 'S3', 'OTH']

COUNTRIES = [
    {'name': 'Russia', 'lat': 55.75, 'lng': 37.62},
    {'name': 'China', 'lat': 39.91, 'lng': 116.40},
    {'name': 'North Korea', 'lat': 39.03, 'lng': 125.75},
    {'name': 'Iran', 'lat': 35.69, 'lng': 51.39},
    {'name': 'Brazil', 'lat': -15.79, 'lng': -47.88},
    {'name': 'Nigeria', 'lat': 9.06, 'lng': 7.49},
    {'name': 'Romania', 'lat': 44.43, 'lng': 26.10},
    {'name': 'Ukraine', 'lat': 50.45, 'lng': 30.52},
    {'name': 'India', 'lat': 28.61, 'lng': 77.21},
    {'name': 'Vietnam', 'lat': 21.03, 'lng': 105.85},
    {'name': 'Indonesia', 'lat': -6.21, 'lng': 106.85},
    {'name': 'Turkey', 'lat': 39.93, 'lng': 32.86},
]

LOG_TEMPLATES = {
    'Normal': [
        '[INFO] Connection established from {ip} on port {port}',
        '[INFO] DNS query resolved for {domain}',
        '[INFO] Successful authentication from {ip}',
        '[INFO] HTTP GET request to {path} - 200 OK',
        '[INFO] TLS handshake completed with {ip}',
        '[INFO] Outbound traffic to {ip}:{port} - {bytes}B transferred',
    ],
    'DDoS': [
        '[ALERT] SYN flood detected from {ip} - {count} packets/sec',
        '[ALERT] UDP amplification attack from {ip}',
        '[CRITICAL] Traffic spike: {count} requests/sec from subnet {subnet}',
        '[ALERT] HTTP flood targeting endpoint {path}',
        '[WARN] Connection rate limit exceeded by {ip}',
    ],
    'SQL Injection': [
        '[ALERT] SQL injection attempt detected in parameter: {param}',
        '[CRITICAL] Malicious payload in POST body from {ip}',
        '[ALERT] UNION SELECT detected from {ip} targeting {path}',
        '[WARN] Suspicious query string from {ip}: {payload}',
    ],
    'Port Scan': [
        '[ALERT] Sequential port scan detected from {ip}',
        '[WARN] SYN scan on ports {port_range} from {ip}',
        '[ALERT] Stealth scan (FIN) detected from {ip}',
        '[INFO] NMAP fingerprint detected from {ip}',
    ],
    'Brute Force': [
        '[ALERT] Multiple failed login attempts from {ip} ({count} tries)',
        '[CRITICAL] SSH brute force attack from {ip}',
        '[ALERT] Password spray attack targeting {service}',
        '[WARN] Account lockout triggered for user {user} from {ip}',
    ],
}


def _random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_domain():
    domains = ['example.com', 'api.service.io', 'cdn.assets.net', 'mail.corp.org',
               'db.internal.local', 'auth.platform.com', 'storage.cloud.io']
    return random.choice(domains)


def generate_training_data(n_samples=5000):
    """Generate synthetic NSL-KDD style training data."""
    data = []
    labels = []

    for _ in range(n_samples):
        attack_type = random.choices(
            ATTACK_TYPES,
            weights=[0.50, 0.15, 0.12, 0.13, 0.10],
            k=1
        )[0]

        if attack_type == 'Normal':
            row = {
                'duration': random.uniform(0, 300),
                'protocol_type': random.choice([0, 1, 2]),
                'src_bytes': random.uniform(0, 5000),
                'dst_bytes': random.uniform(0, 5000),
                'flag': random.choice(range(len(FLAGS))),
                'count': random.randint(1, 50),
                'srv_count': random.randint(1, 30),
                'serror_rate': random.uniform(0, 0.1),
                'rerror_rate': random.uniform(0, 0.1),
                'same_srv_rate': random.uniform(0.8, 1.0),
                'diff_srv_rate': random.uniform(0, 0.2),
                'dst_host_count': random.randint(1, 255),
                'dst_host_srv_count': random.randint(1, 255),
                'dst_host_same_srv_rate': random.uniform(0.7, 1.0),
                'dst_host_diff_srv_rate': random.uniform(0, 0.3),
                'dst_host_serror_rate': random.uniform(0, 0.1),
                'dst_host_rerror_rate': random.uniform(0, 0.1),
            }
        elif attack_type == 'DDoS':
            row = {
                'duration': random.uniform(0, 5),
                'protocol_type': random.choice([0, 1]),
                'src_bytes': random.uniform(0, 500),
                'dst_bytes': random.uniform(0, 100),
                'flag': random.choice([1, 2, 5]),
                'count': random.randint(200, 511),
                'srv_count': random.randint(1, 10),
                'serror_rate': random.uniform(0.7, 1.0),
                'rerror_rate': random.uniform(0, 0.3),
                'same_srv_rate': random.uniform(0.9, 1.0),
                'diff_srv_rate': random.uniform(0, 0.1),
                'dst_host_count': random.randint(200, 255),
                'dst_host_srv_count': random.randint(1, 50),
                'dst_host_same_srv_rate': random.uniform(0.9, 1.0),
                'dst_host_diff_srv_rate': random.uniform(0, 0.1),
                'dst_host_serror_rate': random.uniform(0.7, 1.0),
                'dst_host_rerror_rate': random.uniform(0, 0.2),
            }
        elif attack_type == 'SQL Injection':
            row = {
                'duration': random.uniform(0, 60),
                'protocol_type': 0,
                'src_bytes': random.uniform(500, 15000),
                'dst_bytes': random.uniform(1000, 30000),
                'flag': random.choice([0, 5]),
                'count': random.randint(1, 20),
                'srv_count': random.randint(1, 15),
                'serror_rate': random.uniform(0, 0.3),
                'rerror_rate': random.uniform(0.3, 0.8),
                'same_srv_rate': random.uniform(0.5, 1.0),
                'diff_srv_rate': random.uniform(0, 0.5),
                'dst_host_count': random.randint(1, 100),
                'dst_host_srv_count': random.randint(1, 100),
                'dst_host_same_srv_rate': random.uniform(0.3, 0.8),
                'dst_host_diff_srv_rate': random.uniform(0.2, 0.7),
                'dst_host_serror_rate': random.uniform(0, 0.3),
                'dst_host_rerror_rate': random.uniform(0.3, 0.8),
            }
        elif attack_type == 'Port Scan':
            row = {
                'duration': random.uniform(0, 2),
                'protocol_type': 0,
                'src_bytes': random.uniform(0, 100),
                'dst_bytes': random.uniform(0, 50),
                'flag': random.choice([1, 2, 3]),
                'count': random.randint(100, 511),
                'srv_count': random.randint(50, 255),
                'serror_rate': random.uniform(0.5, 1.0),
                'rerror_rate': random.uniform(0.5, 1.0),
                'same_srv_rate': random.uniform(0, 0.3),
                'diff_srv_rate': random.uniform(0.7, 1.0),
                'dst_host_count': random.randint(200, 255),
                'dst_host_srv_count': random.randint(200, 255),
                'dst_host_same_srv_rate': random.uniform(0, 0.3),
                'dst_host_diff_srv_rate': random.uniform(0.7, 1.0),
                'dst_host_serror_rate': random.uniform(0.5, 1.0),
                'dst_host_rerror_rate': random.uniform(0.5, 1.0),
            }
        else:  # Brute Force
            row = {
                'duration': random.uniform(0, 10),
                'protocol_type': 0,
                'src_bytes': random.uniform(100, 2000),
                'dst_bytes': random.uniform(0, 500),
                'flag': random.choice([0, 1, 5]),
                'count': random.randint(50, 400),
                'srv_count': random.randint(1, 5),
                'serror_rate': random.uniform(0, 0.5),
                'rerror_rate': random.uniform(0.5, 1.0),
                'same_srv_rate': random.uniform(0.9, 1.0),
                'diff_srv_rate': random.uniform(0, 0.1),
                'dst_host_count': random.randint(1, 50),
                'dst_host_srv_count': random.randint(1, 30),
                'dst_host_same_srv_rate': random.uniform(0.8, 1.0),
                'dst_host_diff_srv_rate': random.uniform(0, 0.2),
                'dst_host_serror_rate': random.uniform(0, 0.5),
                'dst_host_rerror_rate': random.uniform(0.5, 1.0),
            }

        # Add small noise
        for key in row:
            if isinstance(row[key], float):
                row[key] += random.gauss(0, 0.01)
                row[key] = max(0, row[key])

        data.append(list(row.values()))
        labels.append(ATTACK_TYPES.index(attack_type))

    return np.array(data), np.array(labels)


def generate_traffic_sample():
    """Generate a single simulated traffic sample for real-time prediction."""
    attack = random.choices(ATTACK_TYPES, weights=[0.6, 0.1, 0.1, 0.1, 0.1], k=1)[0]
    is_attack = attack != 'Normal'

    sample = {
        'duration': random.uniform(0, 300) if not is_attack else random.uniform(0, 10),
        'protocol_type': random.choice([0, 1, 2]),
        'src_bytes': random.uniform(0, 5000),
        'dst_bytes': random.uniform(0, 5000),
        'flag': random.choice(range(len(FLAGS))),
        'count': random.randint(1, 50) if not is_attack else random.randint(100, 511),
        'srv_count': random.randint(1, 30),
        'serror_rate': random.uniform(0, 0.1) if not is_attack else random.uniform(0.5, 1.0),
        'rerror_rate': random.uniform(0, 0.1) if not is_attack else random.uniform(0.3, 1.0),
        'same_srv_rate': random.uniform(0.7, 1.0),
        'diff_srv_rate': random.uniform(0, 0.3),
        'dst_host_count': random.randint(1, 255),
        'dst_host_srv_count': random.randint(1, 255),
        'dst_host_same_srv_rate': random.uniform(0.5, 1.0),
        'dst_host_diff_srv_rate': random.uniform(0, 0.5),
        'dst_host_serror_rate': random.uniform(0, 0.1) if not is_attack else random.uniform(0.5, 1.0),
        'dst_host_rerror_rate': random.uniform(0, 0.1) if not is_attack else random.uniform(0.3, 1.0),
    }

    return {
        'features': list(sample.values()),
        'src_ip': _random_ip(),
        'dst_ip': _random_ip(),
        'protocol': random.choice(PROTOCOLS),
        'service': random.choice(SERVICES),
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'actual_label': attack,
    }


def generate_traffic_batch(n=20):
    """Generate a batch of simulated traffic for the dashboard."""
    return [generate_traffic_sample() for _ in range(n)]


def generate_threat_map_data(n=8):
    """Generate simulated threat origins for the global threat map."""
    threats = []
    for _ in range(n):
        origin = random.choice(COUNTRIES)
        threats.append({
            'country': origin['name'],
            'lat': origin['lat'] + random.uniform(-2, 2),
            'lng': origin['lng'] + random.uniform(-2, 2),
            'attack_type': random.choice(ATTACK_TYPES[1:]),
            'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
            'ip': _random_ip(),
            'timestamp': datetime.now().strftime('%H:%M:%S'),
        })
    return threats


def generate_log_entries(n=5):
    """Generate realistic security log entries."""
    entries = []
    for _ in range(n):
        attack_type = random.choices(
            ATTACK_TYPES,
            weights=[0.5, 0.15, 0.12, 0.13, 0.10],
            k=1
        )[0]

        templates = LOG_TEMPLATES[attack_type]
        template = random.choice(templates)

        entry = template.format(
            ip=_random_ip(),
            port=random.choice([22, 80, 443, 3306, 8080, 8443, 3389]),
            domain=_random_domain(),
            path=random.choice(['/api/login', '/admin', '/wp-admin', '/api/users', '/search']),
            bytes=random.randint(64, 65535),
            count=random.randint(50, 5000),
            subnet=f"{random.randint(1, 223)}.{random.randint(0, 255)}.0.0/16",
            param=random.choice(['id', 'username', 'search', 'page', 'token']),
            payload=random.choice(["' OR 1=1--", "UNION SELECT *", "'; DROP TABLE--"]),
            port_range=f"{random.randint(1, 100)}-{random.randint(1000, 65535)}",
            service=random.choice(['SSH', 'FTP', 'RDP', 'SMTP', 'MySQL']),
            user=random.choice(['admin', 'root', 'user1', 'guest', 'test']),
        )

        entries.append({
            'timestamp': datetime.now().strftime('%H:%M:%S.') + f"{random.randint(0, 999):03d}",
            'message': entry,
            'type': attack_type,
        })

    return entries


def generate_analytics_data():
    """Generate data for the analytics dashboard charts."""
    # Traffic over time (last 30 data points)
    traffic_data = {
        'labels': [(datetime.now() - timedelta(minutes=30-i)).strftime('%H:%M') for i in range(30)],
        'normal': [random.randint(50, 200) for _ in range(30)],
        'malicious': [random.randint(0, 60) for _ in range(30)],
    }

    # Attack type distribution
    attack_dist = {
        'labels': ATTACK_TYPES[1:],
        'values': [random.randint(10, 100) for _ in range(4)],
    }

    return {
        'traffic': traffic_data,
        'attack_distribution': attack_dist,
        'total_scans': random.randint(1000, 9999),
        'threats_blocked': random.randint(50, 500),
        'system_health': random.randint(85, 99),
        'active_connections': random.randint(20, 200),
    }
