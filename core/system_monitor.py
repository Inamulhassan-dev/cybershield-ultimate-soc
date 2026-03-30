"""
CyberShield Ultimate - System Monitor
Process monitoring and management using psutil.
"""

import psutil
import os
import time

# ── Cache to prevent constant re-scanning ──
_process_cache = {'data': [], 'timestamp': 0}
_CACHE_TTL = 5  # seconds


SUSPICIOUS_PROCESS_NAMES = {
    'keylogger', 'spyware', 'trojan', 'backdoor', 'rootkit',
    'cryptominer', 'miner', 'rat', 'ransomware', 'botnet',
    'netcat', 'mimikatz', 'lazagne', 'hashcat', 'ncrack',
}

HIGH_CPU_THRESHOLD = 80.0
HIGH_MEM_THRESHOLD = 80.0


def get_processes():
    """
    List running processes with CPU/RAM stats and threat assessment.
    Uses a 5-second cache to avoid hammering the OS.
    Returns top 50 processes sorted by CPU usage.
    """
    now = time.time()
    if now - _process_cache['timestamp'] < _CACHE_TTL and _process_cache['data']:
        return _process_cache['data']

    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
        try:
            info = proc.info
            pid = info['pid']
            name = info['name'] or 'Unknown'
            cpu = info['cpu_percent'] or 0.0
            mem = info['memory_percent'] or 0.0
            status = info['status'] or 'unknown'
            username = info['username'] or 'N/A'

            # Threat assessment
            is_suspicious = False
            threat_reason = ''

            name_lower = name.lower()
            for suspicious_name in SUSPICIOUS_PROCESS_NAMES:
                if suspicious_name in name_lower:
                    is_suspicious = True
                    threat_reason = f'Suspicious process name matches: {suspicious_name}'
                    break

            if cpu > HIGH_CPU_THRESHOLD:
                is_suspicious = True
                threat_reason = f'Extremely high CPU usage: {cpu:.1f}%'

            if mem > HIGH_MEM_THRESHOLD:
                is_suspicious = True
                threat_reason = f'Extremely high memory usage: {mem:.1f}%'

            processes.append({
                'pid': pid,
                'name': name,
                'cpu_percent': round(cpu, 1),
                'memory_percent': round(mem, 1),
                'status': status,
                'username': username,
                'is_suspicious': is_suspicious,
                'threat_reason': threat_reason,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
    processes = processes[:50]  # Only return top 50

    _process_cache['data'] = processes
    _process_cache['timestamp'] = now
    return processes


def kill_process(pid):
    """
    Terminate a process by PID.

    Returns dict with success status and message.
    """
    try:
        pid = int(pid)
        # Safety: prevent killing critical system processes
        if pid in (0, 4) or pid == os.getpid():
            return {
                'success': False,
                'message': f'Cannot terminate protected process (PID: {pid})',
            }

        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()

        # Wait up to 3 seconds for graceful termination
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()

        return {
            'success': True,
            'message': f'Process "{proc_name}" (PID: {pid}) terminated successfully',
        }

    except psutil.NoSuchProcess:
        return {
            'success': False,
            'message': f'Process with PID {pid} not found',
        }
    except psutil.AccessDenied:
        return {
            'success': False,
            'message': f'Access denied: insufficient permissions to kill PID {pid}',
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Error: {str(e)}',
        }


def get_system_info():
    """Get overall system resource information."""
    cpu_percent = psutil.cpu_percent(interval=0)  # Non-blocking
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()

    return {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'memory_used_gb': round(memory.used / (1024 ** 3), 2),
        'memory_total_gb': round(memory.total / (1024 ** 3), 2),
        'disk_percent': disk.percent,
        'disk_used_gb': round(disk.used / (1024 ** 3), 2),
        'disk_total_gb': round(disk.total / (1024 ** 3), 2),
        'net_bytes_sent': net.bytes_sent,
        'net_bytes_recv': net.bytes_recv,
        'boot_time': psutil.boot_time(),
    }
