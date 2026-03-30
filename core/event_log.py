"""
CyberShield Ultimate - Real Event Log Reader
Reads actual Windows Security/System event logs for the live log feed.
Falls back to wevtutil CLI if pywin32 is not available.
"""

import subprocess
import re
import xml.etree.ElementTree as ET
from datetime import datetime

# Try pywin32 for direct Event Log access
_PYWIN32_AVAILABLE = False
try:
    import win32evtlog
    import win32evtlogutil
    _PYWIN32_AVAILABLE = True
except ImportError:
    pass


# Severity mapping for Windows event levels
LEVEL_MAP = {
    1: 'critical',   # Critical
    2: 'alert',      # Error
    3: 'warning',    # Warning
    4: 'info',       # Information
    0: 'info',       # LogAlways
}

# Event IDs we care about
SECURITY_EVENT_IDS = {
    # Logon events
    4624: ('info', 'Successful logon: {user} from {ip}'),
    4625: ('alert', 'Failed logon attempt: {user} from {ip}'),
    4634: ('info', 'User logoff: {user}'),
    4648: ('warning', 'Explicit credentials logon: {user}'),
    # Account management
    4720: ('warning', 'New user account created: {user}'),
    4722: ('info', 'User account enabled: {user}'),
    4725: ('warning', 'User account disabled: {user}'),
    4726: ('alert', 'User account deleted: {user}'),
    4740: ('alert', 'Account locked out: {user}'),
    # Privilege use
    4672: ('info', 'Special privileges assigned to logon: {user}'),
    4673: ('warning', 'Privileged service called'),
    # Object access
    4663: ('info', 'Object access attempt'),
    # Policy changes
    4719: ('warning', 'System audit policy changed'),
    4946: ('warning', 'Firewall rule added'),
    4947: ('info', 'Firewall rule modified'),
    4948: ('warning', 'Firewall rule deleted'),
    4950: ('info', 'Windows Firewall setting changed'),
    # Process events
    4688: ('info', 'New process created: {process}'),
    4689: ('info', 'Process terminated: {process}'),
}


def _parse_wevtutil_xml(xml_str):
    """Parse a single event XML from wevtutil."""
    try:
        root = ET.fromstring(xml_str)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        system = root.find('e:System', ns)
        if system is None:
            return None

        event_id_elem = system.find('e:EventID', ns)
        event_id = int(event_id_elem.text) if event_id_elem is not None else 0

        level_elem = system.find('e:Level', ns)
        level = int(level_elem.text) if level_elem is not None else 4

        time_elem = system.find('e:TimeCreated', ns)
        timestamp = ''
        if time_elem is not None:
            sys_time = time_elem.get('SystemTime', '')
            try:
                dt = datetime.fromisoformat(sys_time.replace('Z', '+00:00'))
                timestamp = dt.strftime('%H:%M:%S')
            except Exception:
                timestamp = sys_time[:8] if len(sys_time) >= 8 else '--:--:--'

        provider_elem = system.find('e:Provider', ns)
        source = provider_elem.get('Name', 'Unknown') if provider_elem is not None else 'Unknown'

        # Extract event data
        event_data = root.find('e:EventData', ns)
        data_dict = {}
        if event_data is not None:
            for data_elem in event_data.findall('e:Data', ns):
                name = data_elem.get('Name', '')
                value = data_elem.text or ''
                if name:
                    data_dict[name] = value

        # Build human-readable message
        entry_type = LEVEL_MAP.get(level, 'info')

        if event_id in SECURITY_EVENT_IDS:
            sev, template = SECURITY_EVENT_IDS[event_id]
            entry_type = sev
            try:
                message = template.format(
                    user=data_dict.get('TargetUserName', data_dict.get('SubjectUserName', 'Unknown')),
                    ip=data_dict.get('IpAddress', data_dict.get('WorkstationName', 'local')),
                    process=data_dict.get('NewProcessName', data_dict.get('ProcessName', 'unknown')),
                )
            except (KeyError, IndexError):
                message = f'Event {event_id} from {source}'
        else:
            message = f'Event {event_id} from {source}'

        level_prefix = {
            'critical': '[CRITICAL]',
            'alert': '[ALERT]',
            'warning': '[WARN]',
            'info': '[INFO]',
        }

        return {
            'timestamp': timestamp,
            'message': f'{level_prefix.get(entry_type, "[INFO]")} {message}',
            'type': entry_type,
            'event_id': event_id,
            'source': source,
        }
    except ET.ParseError:
        return None


def get_real_logs(n=10):
    """
    Get real Windows Event Log entries.
    Tries Security log first, then System log.
    """
    entries = []

    # Try Security log (requires admin), then System log
    for log_name in ['Security', 'System']:
        try:
            result = subprocess.run(
                ['wevtutil', 'qe', log_name,
                 '/c:' + str(n * 2),  # Get extra to filter
                 '/rd:true',  # Most recent first
                 '/f:xml'],
                capture_output=True, text=True, timeout=10,
                encoding='utf-8', errors='replace'
            )

            if result.returncode != 0:
                continue

            # Parse individual events from the output
            xml_events = re.findall(r'<Event\s.*?</Event>', result.stdout, re.DOTALL)

            for xml_str in xml_events:
                entry = _parse_wevtutil_xml(xml_str)
                if entry:
                    entries.append(entry)

                if len(entries) >= n:
                    break

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            continue

        if entries:
            break

    # If no real logs available, return system notifications
    if not entries:
        entries = [
            {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': '[INFO] CyberShield monitoring active — Windows Event Log access limited',
                'type': 'info',
            },
            {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': '[INFO] Run as Administrator for full Security Event Log access',
                'type': 'info',
            },
        ]

    return entries[:n]
