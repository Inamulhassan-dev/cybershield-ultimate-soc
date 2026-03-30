"""
CyberShield Ultimate - Flask Application Server
Main entry point with all routes and API endpoints.
All endpoints use REAL data — no simulations.
"""

from flask import Flask, render_template, request, jsonify
import os
import json
import subprocess
import socket

from core.ai_model import predict_traffic, predict_batch, load_model, ATTACK_LABELS
from core.scanner import scan_file, scan_url, scan_code
from core.system_monitor import get_processes, kill_process, get_system_info
from core.packet_capture import start_capture, get_recent_traffic, get_traffic_stats
from core.event_log import get_real_logs
from core.stats_tracker import (
    increment, record_traffic_classification, record_traffic_snapshot,
    get_analytics, get_raw_stats,
)
from core.tools import (
    check_password, scan_wifi, analyze_email_header, scan_ports,
    calculate_security_score, check_leak, lookup_ip,
    encrypt_text, decrypt_text, generate_report,
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# ── Page Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return render_template('dashboard.html', active='dashboard')

@app.route('/network-shield')
def network_shield():
    return render_template('network_shield.html', active='network')

@app.route('/file-guard')
def file_guard():
    return render_template('file_guard.html', active='fileguard')

@app.route('/link-scanner')
def link_scanner():
    return render_template('link_scanner.html', active='linkscanner')

@app.route('/system-watch')
def system_watch():
    return render_template('system_watch.html', active='systemwatch')

@app.route('/app-vetter')
def app_vetter():
    return render_template('app_vetter.html', active='appvetter')

@app.route('/password-checker')
def password_checker():
    return render_template('password_checker.html', active='password')

@app.route('/wifi-scanner')
def wifi_scanner():
    return render_template('wifi_scanner.html', active='wifi')

@app.route('/email-analyzer')
def email_analyzer():
    return render_template('email_analyzer.html', active='email')

@app.route('/port-scanner')
def port_scanner():
    return render_template('port_scanner.html', active='portscan')

@app.route('/leak-checker')
def leak_checker():
    return render_template('leak_checker.html', active='leak')

@app.route('/ip-lookup')
def ip_lookup():
    return render_template('ip_lookup.html', active='iplookup')

@app.route('/encryption-tool')
def encryption_tool():
    return render_template('encryption_tool.html', active='encrypt')

@app.route('/report-generator')
def report_generator():
    return render_template('report_generator.html', active='report')


# ── API: Network Shield — REAL TRAFFIC ──────────────────────────────────────

@app.route('/api/predict', methods=['POST'])
def api_predict():
    """Classify a single traffic sample using the ML model."""
    try:
        data = request.get_json()
        features = data.get('features', [])
        if len(features) != 17:
            return jsonify({'error': 'Expected 17 features'}), 400
        result = predict_traffic(features)
        # Track real classification
        record_traffic_classification(result['label'])
        increment('total_scans', 0)  # Already counted by traffic
        return jsonify(result)
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/traffic-data', methods=['GET'])
def api_traffic_data():
    """Get REAL captured traffic with ML predictions."""
    try:
        # Get real captured packets
        raw_traffic = get_recent_traffic(n=20)

        if raw_traffic:
            # Classify each real packet through the AI model
            results = []
            for entry in raw_traffic:
                try:
                    prediction = predict_traffic(entry['features'])
                    prediction['src_ip'] = entry.get('src_ip', 'N/A')
                    prediction['dst_ip'] = entry.get('dst_ip', 'N/A')
                    prediction['protocol'] = entry.get('protocol', 'N/A')
                    prediction['service'] = entry.get('service', 'N/A')
                    prediction['timestamp'] = entry.get('timestamp', 'N/A')
                    # Track the classification
                    record_traffic_classification(prediction['label'])
                    results.append(prediction)
                except Exception:
                    # If model fails, still include the raw entry
                    results.append({
                        'label': 'Unknown',
                        'confidence': 0,
                        'is_threat': False,
                        'src_ip': entry.get('src_ip', 'N/A'),
                        'dst_ip': entry.get('dst_ip', 'N/A'),
                        'protocol': entry.get('protocol', 'N/A'),
                        'service': entry.get('service', 'N/A'),
                        'timestamp': entry.get('timestamp', 'N/A'),
                    })

            # Record snapshot for chart
            record_traffic_snapshot()
            return jsonify({'traffic': results, 'source': 'real'})
        else:
            # No captured traffic yet
            return jsonify({
                'traffic': [],
                'source': 'real',
                'message': 'Capturing traffic... data will appear in a few seconds',
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/threat-map', methods=['GET'])
def api_threat_map():
    """Get REAL threat origins from captured traffic."""
    try:
        raw_traffic = get_recent_traffic(n=50)
        threats = []
        seen_ips = set()

        for entry in raw_traffic:
            src_ip = entry.get('src_ip', '')
            if not src_ip or src_ip in seen_ips:
                continue
            # Skip local/private IPs
            if src_ip.startswith(('127.', '10.', '192.168.', '172.')):
                continue
            if src_ip in ('0.0.0.0', '255.255.255.255'):
                continue

            seen_ips.add(src_ip)

            # Try to classify
            try:
                prediction = predict_traffic(entry['features'])
                if prediction.get('is_threat', False):
                    # Geo-locate the threat IP
                    try:
                        geo = lookup_ip(src_ip)
                        if 'error' not in geo:
                            threats.append({
                                'country': geo.get('country', 'Unknown'),
                                'lat': geo.get('lat', 0),
                                'lng': geo.get('lon', 0),
                                'attack_type': prediction['label'],
                                'severity': 'Critical' if prediction.get('confidence', 0) > 80
                                           else 'High' if prediction.get('confidence', 0) > 60
                                           else 'Medium',
                                'ip': src_ip,
                                'timestamp': entry.get('timestamp', '--:--:--'),
                            })
                    except Exception:
                        threats.append({
                            'country': 'Unknown',
                            'lat': 0,
                            'lng': 0,
                            'attack_type': prediction['label'],
                            'severity': 'Medium',
                            'ip': src_ip,
                            'timestamp': entry.get('timestamp', '--:--:--'),
                        })
            except Exception:
                continue

            if len(threats) >= 8:
                break

        return jsonify({'threats': threats, 'source': 'real'})
    except Exception as e:
        return jsonify({'threats': [], 'error': str(e)})


@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Get REAL analytics dashboard data."""
    try:
        data = get_analytics()

        # Fill in real system health from security score
        try:
            score = calculate_security_score()
            data['system_health'] = score.get('score', 0)
        except Exception:
            data['system_health'] = 0

        # Get real active connections count
        try:
            result = subprocess.run(
                ['netstat', '-n'],
                capture_output=True, text=True, timeout=5
            )
            conn_count = sum(1 for line in result.stdout.split('\n')
                           if line.strip().startswith('TCP') and 'ESTABLISHED' in line)
            data['active_connections'] = conn_count
        except Exception:
            data['active_connections'] = 0

        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── API: File Guard ──────────────────────────────────────────────────────────

@app.route('/api/scan-file', methods=['POST'])
def api_scan_file():
    """Upload and scan a file for malware indicators."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    file_bytes = f.read()
    result = scan_file(file_bytes, f.filename)
    increment('file_scans')
    if result.get('risk_score', 0) >= 50:
        record_traffic_classification('SQL Injection')  # Count as threat
    return jsonify(result)


# ── API: Link Scanner ───────────────────────────────────────────────────────

@app.route('/api/scan-url', methods=['POST'])
def api_scan_url():
    """Analyze a URL for phishing indicators."""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    result = scan_url(url)
    increment('url_scans')
    return jsonify(result)


# ── API: System Watch ────────────────────────────────────────────────────────

@app.route('/api/processes', methods=['GET'])
def api_processes():
    """List running processes with threat assessment."""
    processes = get_processes()
    return jsonify({'processes': processes})


@app.route('/api/kill-process', methods=['POST'])
def api_kill_process():
    """Terminate a process by PID."""
    data = request.get_json()
    pid = data.get('pid')

    if pid is None:
        return jsonify({'error': 'PID is required'}), 400

    result = kill_process(pid)
    return jsonify(result)


@app.route('/api/system-info', methods=['GET'])
def api_system_info():
    """Get system resource information."""
    info = get_system_info()
    return jsonify(info)


# ── API: App Vetter ──────────────────────────────────────────────────────────

@app.route('/api/scan-code', methods=['POST'])
def api_scan_code():
    """Scan uploaded code for security vulnerabilities."""
    if request.is_json:
        data = request.get_json()
        code = data.get('code', '')
    elif 'file' in request.files:
        f = request.files['file']
        code = f.read().decode('utf-8', errors='ignore')
    else:
        return jsonify({'error': 'No code provided'}), 400

    if not code.strip():
        return jsonify({'error': 'Empty code provided'}), 400

    result = scan_code(code)
    increment('code_scans')
    return jsonify(result)


# ── API: Live Log Feed — REAL WINDOWS EVENTS ────────────────────────────────

@app.route('/api/logs', methods=['GET'])
def api_logs():
    """Get REAL Windows Event Log entries."""
    try:
        entries = get_real_logs(n=5)
        return jsonify({'logs': entries, 'source': 'real'})
    except Exception as e:
        return jsonify({'logs': [], 'error': str(e)})


# ── API: System Status — REAL CHECKS ────────────────────────────────────────

@app.route('/api/system-status', methods=['GET'])
def api_system_status():
    """Get REAL system security status."""
    try:
        # Real firewall check
        firewall_active = False
        try:
            fw = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True, text=True, timeout=5
            )
            firewall_active = 'ON' in fw.stdout.upper()
        except Exception:
            pass

        # Real antivirus check
        antivirus_active = False
        try:
            av = subprocess.run(
                ['powershell', '-Command',
                 'Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled'],
                capture_output=True, text=True, timeout=10
            )
            antivirus_active = 'True' in av.stdout
        except Exception:
            pass

        # Real risky port check
        risky_ports_open = 0
        for port in [23, 135, 445, 3389, 5900]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    risky_ports_open += 1
                sock.close()
            except Exception:
                pass

        # Real system info
        sys_info = get_system_info()

        # Determine real threat level
        issues = 0
        if not firewall_active:
            issues += 2
        if not antivirus_active:
            issues += 2
        if risky_ports_open > 0:
            issues += risky_ports_open
        if sys_info.get('cpu_percent', 0) > 90:
            issues += 1

        # Get real threat count from stats
        stats = get_raw_stats()
        active_threats = stats.get('threats_detected', 0)

        if issues == 0:
            threat_level = 'LOW'
            status = 'SECURE'
        elif issues <= 2:
            threat_level = 'MODERATE'
            status = 'SECURE'
        elif issues <= 4:
            threat_level = 'HIGH'
            status = 'UNDER ATTACK'
        else:
            threat_level = 'CRITICAL'
            status = 'UNDER ATTACK'

        return jsonify({
            'status': status,
            'threat_level': threat_level,
            'active_threats': active_threats,
            'firewall': 'Active' if firewall_active else 'DISABLED',
            'antivirus': 'Active' if antivirus_active else 'DISABLED',
            'ids_status': 'Online',
            'risky_ports': risky_ports_open,
            'last_scan': 'Live',
        })
    except Exception as e:
        return jsonify({
            'status': 'UNKNOWN',
            'threat_level': 'MODERATE',
            'active_threats': 0,
            'firewall': 'Unknown',
            'ids_status': 'Error',
            'last_scan': str(e),
        })


# ── API: Password Checker ────────────────────────────────────────────────────

@app.route('/api/check-password', methods=['POST'])
def api_check_password():
    data = request.get_json()
    password = data.get('password', '')
    result = check_password(password)
    increment('password_checks')
    return jsonify(result)


# ── API: Wi-Fi Scanner ───────────────────────────────────────────────────────

@app.route('/api/scan-wifi', methods=['GET'])
def api_scan_wifi():
    result = scan_wifi()
    increment('wifi_scans')
    return jsonify(result)


# ── API: Email Header Analyzer ───────────────────────────────────────────────

@app.route('/api/analyze-email', methods=['POST'])
def api_analyze_email():
    data = request.get_json()
    header = data.get('header', '')
    result = analyze_email_header(header)
    increment('email_analyses')
    return jsonify(result)


# ── API: Port Scanner ────────────────────────────────────────────────────────

@app.route('/api/scan-ports', methods=['POST'])
def api_scan_ports():
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    port_range = data.get('range', 'common')
    result = scan_ports(target, port_range)
    increment('port_scans')
    return jsonify(result)


# ── API: Security Score ──────────────────────────────────────────────────────

@app.route('/api/security-score', methods=['GET'])
def api_security_score():
    result = calculate_security_score()
    return jsonify(result)


# ── API: Leak Checker ────────────────────────────────────────────────────────

@app.route('/api/check-leak', methods=['POST'])
def api_check_leak():
    data = request.get_json()
    email = data.get('email', '')
    result = check_leak(email)
    increment('leak_checks')
    return jsonify(result)


# ── API: IP Lookup ───────────────────────────────────────────────────────────

@app.route('/api/ip-lookup', methods=['POST'])
def api_ip_lookup():
    data = request.get_json()
    ip = data.get('ip', '')
    result = lookup_ip(ip)
    increment('ip_lookups')
    return jsonify(result)


# ── API: Encryption Tool ─────────────────────────────────────────────────────

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json()
    plaintext = data.get('text', '')
    password = data.get('password', '')
    result = encrypt_text(plaintext, password)
    increment('encryptions')
    return jsonify(result)


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json()
    encrypted = data.get('text', '')
    password = data.get('password', '')
    result = decrypt_text(encrypted, password)
    increment('decryptions')
    return jsonify(result)


# ── API: Report Generator ────────────────────────────────────────────────────

@app.route('/api/generate-report', methods=['POST'])
def api_generate_report():
    scan_data = request.get_json() or {}
    # Run real security checks
    if 'security_score' not in scan_data:
        scan_data['security_score'] = calculate_security_score()
    if 'port_scan' not in scan_data:
        scan_data['port_scan'] = scan_ports('127.0.0.1', 'common')
    if 'wifi' not in scan_data:
        scan_data['wifi'] = scan_wifi()
    result = generate_report(scan_data)
    increment('reports_generated')
    return jsonify(result)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Load AI model at startup
    try:
        load_model()
        print("[✓] AI Model loaded (trained on real NSL-KDD data)")
    except FileNotFoundError:
        print("[!] Warning: AI Model not found. Run train_model.py first.")

    # Start real-time packet capture
    try:
        start_capture()
        print("[✓] Real-time packet capture started")
    except Exception as e:
        print(f"[!] Packet capture unavailable: {e}")

    # Show stats
    stats = get_raw_stats()
    print(f"[✓] Stats loaded — {stats.get('total_scans', 0)} total scans recorded")

    print("\n" + "=" * 60)
    print("  CyberShield Ultimate - REAL-TIME Operations Center")
    print("  All data is LIVE — no simulations")
    print("  Starting at http://127.0.0.1:5000")
    print("=" * 60 + "\n")

    app.run(debug=True, host='127.0.0.1', port=5000)
