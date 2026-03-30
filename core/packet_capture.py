"""
CyberShield Ultimate - Real Packet Capture
Captures real network packets using scapy (if available) or falls back
to netstat-based connection monitoring for non-admin environments.
"""

import threading
import time
import socket
import subprocess
import re
from datetime import datetime
from collections import deque

# Try to import scapy for real packet capture
_SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    conf.verb = 0  # Suppress scapy output
    _SCAPY_AVAILABLE = True
except ImportError:
    pass

# Ring buffer of captured traffic (max 200 entries)
_traffic_buffer = deque(maxlen=200)
_capture_thread = None
_capture_running = False
_capture_lock = threading.Lock()

# Protocol mappings
PROTOCOL_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
SERVICE_MAP = {
    80: 'http', 443: 'https', 21: 'ftp', 22: 'ssh',
    23: 'telnet', 25: 'smtp', 53: 'dns', 110: 'pop3',
    143: 'imap', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
    8080: 'http-alt', 8443: 'https-alt', 27017: 'mongodb',
}

# FLAGS for TCP
TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR',
}


def _packet_to_features(pkt):
    """Convert a real scapy packet into our 17-feature vector + metadata."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    protocol_num = ip.proto
    protocol = PROTOCOL_MAP.get(protocol_num, 'Other')

    # Basic features
    src_bytes = len(pkt)
    dst_bytes = 0
    duration = 0
    flag = 0
    src_port = 0
    dst_port = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        dst_bytes = len(bytes(tcp.payload)) if tcp.payload else 0
        # Map TCP flags to our flag encoding
        flags = str(tcp.flags)
        if 'S' in flags and 'A' not in flags:
            flag = 1  # SYN
        elif 'S' in flags and 'A' in flags:
            flag = 0  # SF (established)
        elif 'R' in flags:
            flag = 2  # REJ/RST
        elif 'F' in flags:
            flag = 3  # FIN
        else:
            flag = 0  # Normal
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        dst_bytes = len(bytes(udp.payload)) if udp.payload else 0
        flag = 0
        protocol_num = 1  # Map to our encoding

    # Determine service
    service = SERVICE_MAP.get(dst_port, SERVICE_MAP.get(src_port, 'other'))

    # Build 17-feature vector matching our model
    features = [
        float(duration),           # duration
        float(protocol_num % 3),   # protocol_type (0=TCP, 1=UDP, 2=ICMP)
        float(src_bytes),          # src_bytes
        float(dst_bytes),          # dst_bytes
        float(flag),               # flag
        1.0,                       # count (single packet)
        1.0,                       # srv_count
        0.0,                       # serror_rate (computed in aggregation)
        0.0,                       # rerror_rate
        1.0,                       # same_srv_rate
        0.0,                       # diff_srv_rate
        1.0,                       # dst_host_count
        1.0,                       # dst_host_srv_count
        1.0,                       # dst_host_same_srv_rate
        0.0,                       # dst_host_diff_srv_rate
        0.0,                       # dst_host_serror_rate
        0.0,                       # dst_host_rerror_rate
    ]

    return {
        'features': features,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'service': service,
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'size': src_bytes,
    }


def _scapy_callback(pkt):
    """Callback for scapy sniffer."""
    entry = _packet_to_features(pkt)
    if entry:
        with _capture_lock:
            _traffic_buffer.append(entry)


def _start_scapy_capture():
    """Start real-time packet capture with scapy."""
    global _capture_running
    _capture_running = True
    try:
        sniff(
            prn=_scapy_callback,
            store=False,
            stop_filter=lambda x: not _capture_running,
            count=0,
        )
    except PermissionError:
        print("[!] Packet capture requires Administrator privileges.")
        print("    Falling back to netstat-based monitoring.")
        _capture_running = False
        _start_netstat_monitor()
    except Exception as e:
        print(f"[!] Packet capture error: {e}")
        _capture_running = False
        _start_netstat_monitor()


def _start_netstat_monitor():
    """Fallback: monitor connections using netstat (no admin required)."""
    global _capture_running
    _capture_running = True

    seen_connections = set()

    while _capture_running:
        try:
            result = subprocess.run(
                ['netstat', '-n', '-p', 'TCP'],
                capture_output=True, text=True, timeout=5
            )

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line.startswith('TCP'):
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                local = parts[1]
                remote = parts[2]
                state = parts[3]

                # Parse IPs and ports
                local_ip, _, local_port = local.rpartition(':')
                remote_ip, _, remote_port = remote.rpartition(':')

                conn_key = f"{local}:{remote}"
                if conn_key in seen_connections:
                    continue
                seen_connections.add(conn_key)

                try:
                    dst_port = int(remote_port)
                    src_port = int(local_port)
                except ValueError:
                    continue

                # Skip local-only connections
                if remote_ip in ('0.0.0.0', '127.0.0.1', '[::]', '[::1]'):
                    continue

                service = SERVICE_MAP.get(dst_port, 'other')

                # Map TCP state to flag
                flag_map = {
                    'ESTABLISHED': 0, 'SYN_SENT': 1, 'SYN_RECEIVED': 1,
                    'CLOSE_WAIT': 3, 'TIME_WAIT': 3, 'LISTENING': 0,
                }
                flag = flag_map.get(state, 0)

                features = [
                    0.0,                       # duration
                    0.0,                       # protocol_type (TCP)
                    0.0,                       # src_bytes (unknown from netstat)
                    0.0,                       # dst_bytes
                    float(flag),               # flag
                    1.0, 1.0,                  # count, srv_count
                    0.0, 0.0,                  # serror_rate, rerror_rate
                    1.0, 0.0,                  # same_srv_rate, diff_srv_rate
                    1.0, 1.0,                  # dst_host_count, dst_host_srv_count
                    1.0, 0.0,                  # dst_host_same_srv_rate, dst_host_diff_srv_rate
                    0.0, 0.0,                  # dst_host_serror_rate, dst_host_rerror_rate
                ]

                entry = {
                    'features': features,
                    'src_ip': local_ip,
                    'dst_ip': remote_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': 'TCP',
                    'service': service,
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'state': state,
                    'size': 0,
                }

                with _capture_lock:
                    _traffic_buffer.append(entry)

            # Keep only recent connections to detect new ones
            if len(seen_connections) > 1000:
                seen_connections.clear()

        except Exception as e:
            pass

        time.sleep(3)  # Poll every 3 seconds


def start_capture():
    """Start packet capture in a background thread."""
    global _capture_thread, _capture_running

    if _capture_running:
        return

    if _SCAPY_AVAILABLE:
        print("[*] Starting real-time packet capture (scapy)...")
        _capture_thread = threading.Thread(target=_start_scapy_capture, daemon=True)
    else:
        print("[*] Scapy not available. Using netstat-based connection monitoring...")
        _capture_thread = threading.Thread(target=_start_netstat_monitor, daemon=True)

    _capture_thread.start()


def stop_capture():
    """Stop packet capture."""
    global _capture_running
    _capture_running = False


def get_recent_traffic(n=20):
    """Get the most recent N captured traffic entries."""
    with _capture_lock:
        entries = list(_traffic_buffer)

    # Return the last N entries
    return entries[-n:] if len(entries) > n else entries


def get_traffic_stats():
    """Get statistics about captured traffic."""
    with _capture_lock:
        entries = list(_traffic_buffer)

    total = len(entries)
    protocols = {}
    unique_ips = set()

    for e in entries:
        proto = e.get('protocol', 'Unknown')
        protocols[proto] = protocols.get(proto, 0) + 1
        unique_ips.add(e.get('dst_ip', ''))
        unique_ips.add(e.get('src_ip', ''))

    return {
        'total_captured': total,
        'protocols': protocols,
        'unique_ips': len(unique_ips),
        'capture_method': 'scapy' if _SCAPY_AVAILABLE else 'netstat',
        'is_running': _capture_running,
    }


def is_capture_available():
    """Check if packet capture is available."""
    return _SCAPY_AVAILABLE or True  # netstat fallback always available
