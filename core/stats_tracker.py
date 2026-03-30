"""
CyberShield Ultimate - Real Stats Tracker
Tracks actual scan counts, threats detected, and system health.
Persists data to a JSON file so it survives server restarts.
"""

import json
import os
import threading
from datetime import datetime

STATS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'stats.json')
_lock = threading.Lock()

# Default stats structure
_DEFAULT_STATS = {
    'total_scans': 0,
    'file_scans': 0,
    'url_scans': 0,
    'code_scans': 0,
    'password_checks': 0,
    'port_scans': 0,
    'email_analyses': 0,
    'ip_lookups': 0,
    'leak_checks': 0,
    'encryptions': 0,
    'decryptions': 0,
    'wifi_scans': 0,
    'reports_generated': 0,
    'threats_detected': 0,
    'normal_traffic': 0,
    'malicious_traffic': 0,
    'traffic_history': [],       # [{time, normal, malicious}]
    'attack_distribution': {     # real counts per type
        'DDoS': 0,
        'SQL Injection': 0,
        'Port Scan': 0,
        'Brute Force': 0,
    },
    'started_at': None,
    'last_updated': None,
}

_stats = None


def _load_stats():
    """Load stats from disk."""
    global _stats
    if _stats is not None:
        return _stats

    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                saved = json.load(f)
            # Merge with defaults (in case new fields were added)
            _stats = {**_DEFAULT_STATS, **saved}
        except (json.JSONDecodeError, IOError):
            _stats = {**_DEFAULT_STATS}
    else:
        _stats = {**_DEFAULT_STATS}

    if not _stats['started_at']:
        _stats['started_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return _stats


def _save_stats():
    """Save stats to disk."""
    if _stats is None:
        return
    try:
        _stats['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(STATS_FILE, 'w') as f:
            json.dump(_stats, f, indent=2)
    except IOError:
        pass


def increment(counter_name, amount=1):
    """Increment a counter by amount."""
    with _lock:
        stats = _load_stats()
        if counter_name in stats:
            stats[counter_name] += amount
        stats['total_scans'] += amount
        _save_stats()


def record_traffic_classification(label):
    """Record a traffic classification result."""
    with _lock:
        stats = _load_stats()
        if label == 'Normal':
            stats['normal_traffic'] += 1
        else:
            stats['malicious_traffic'] += 1
            stats['threats_detected'] += 1
            if label in stats['attack_distribution']:
                stats['attack_distribution'][label] += 1
        _save_stats()


def record_traffic_snapshot():
    """Record a point-in-time snapshot for the traffic chart."""
    with _lock:
        stats = _load_stats()
        snapshot = {
            'time': datetime.now().strftime('%H:%M'),
            'normal': stats['normal_traffic'],
            'malicious': stats['malicious_traffic'],
        }
        stats['traffic_history'].append(snapshot)
        # Keep last 30 snapshots
        if len(stats['traffic_history']) > 30:
            stats['traffic_history'] = stats['traffic_history'][-30:]
        _save_stats()


def get_analytics():
    """Get real analytics data for the dashboard."""
    with _lock:
        stats = _load_stats()

    # Build traffic chart data from history
    history = stats.get('traffic_history', [])
    if history:
        labels = [h['time'] for h in history]
        normal_data = []
        malicious_data = []
        prev_n = 0
        prev_m = 0
        for h in history:
            n = h['normal'] - prev_n
            m = h['malicious'] - prev_m
            normal_data.append(max(0, n))
            malicious_data.append(max(0, m))
            prev_n = h['normal']
            prev_m = h['malicious']
    else:
        labels = [datetime.now().strftime('%H:%M')]
        normal_data = [stats.get('normal_traffic', 0)]
        malicious_data = [stats.get('malicious_traffic', 0)]

    traffic_data = {
        'labels': labels,
        'normal': normal_data,
        'malicious': malicious_data,
    }

    attack_dist = stats.get('attack_distribution', {})
    attack_distribution = {
        'labels': list(attack_dist.keys()),
        'values': list(attack_dist.values()),
    }

    return {
        'traffic': traffic_data,
        'attack_distribution': attack_distribution,
        'total_scans': stats['total_scans'],
        'threats_blocked': stats['threats_detected'],
        'system_health': 0,  # Will be filled by real security score
        'active_connections': 0,  # Will be filled by real netstat count
    }


def get_raw_stats():
    """Get all raw stats."""
    with _lock:
        return {**_load_stats()}
