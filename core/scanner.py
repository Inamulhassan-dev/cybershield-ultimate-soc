"""
CyberShield Ultimate - Scanner Module
File hash computation, URL phishing detection, and code vulnerability scanning.
"""

import hashlib
import re
import os
from urllib.parse import urlparse


# ── File Guard: Malware Scanner ──────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.msi', '.vbs',
    '.js', '.wsf', '.ps1', '.jar', '.dll', '.sys', '.inf',
}

SUSPICIOUS_CONTENT_PATTERNS = [
    (r'powershell\s+-\w*e\w*\s', 'PowerShell encoded command detected'),
    (r'cmd\.exe\s*/c', 'CMD execution detected'),
    (r'<script[^>]*>.*?(eval|document\.write|unescape)', 'Suspicious JavaScript in document'),
    (r'(?:WScript|Shell)\.(?:Run|Exec)', 'Windows Script Host execution'),
    (r'(?:HKEY_|RegWrite|RegDelete)', 'Registry manipulation detected'),
    (r'(?:Net\.WebClient|Invoke-WebRequest|curl|wget)', 'Network download command detected'),
    (r'(?:keylog|screenlog|clipboard)', 'Potential spyware behavior'),
    (r'CreateObject\s*\(\s*["\'](?:WScript|Shell)', 'COM object creation detected'),
    (r'base64[_\-]?(?:encode|decode)', 'Base64 encoding/decoding detected'),
    (r'(?:\\x[0-9a-fA-F]{2}){4,}', 'Hex-encoded shellcode pattern'),
]

KNOWN_MALICIOUS_HASHES = {
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # empty file
    '44d88612fea8a8f36de82e1278abb02f',  # EICAR test
}


def scan_file(file_bytes, filename):
    """
    Scan a file for potential malware indicators.

    Returns dict with hash, risk_score (0-100), verdict, and findings.
    """
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    file_size = len(file_bytes)
    ext = os.path.splitext(filename)[1].lower()

    findings = []
    risk_score = 0

    # Check known hashes
    if sha256_hash in KNOWN_MALICIOUS_HASHES or md5_hash in KNOWN_MALICIOUS_HASHES:
        findings.append({'type': 'critical', 'message': 'Hash matches known malware signature'})
        risk_score += 80

    # Check extension
    if ext in SUSPICIOUS_EXTENSIONS:
        findings.append({'type': 'warning', 'message': f'Suspicious file extension: {ext}'})
        risk_score += 20

    # Check file size anomalies
    if file_size == 0:
        findings.append({'type': 'info', 'message': 'Empty file detected'})
        risk_score += 5
    elif file_size < 100:
        findings.append({'type': 'info', 'message': 'Unusually small file'})
        risk_score += 5

    # Content analysis (try to decode as text)
    try:
        content = file_bytes.decode('utf-8', errors='ignore')
        for pattern, description in SUSPICIOUS_CONTENT_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({'type': 'warning', 'message': description})
                risk_score += 15
    except Exception:
        pass

    # Double extension check
    parts = filename.split('.')
    if len(parts) > 2:
        findings.append({'type': 'warning', 'message': f'Double extension detected: {filename}'})
        risk_score += 15

    risk_score = min(risk_score, 100)
    verdict = 'Malicious' if risk_score >= 50 else 'Suspicious' if risk_score >= 25 else 'Safe'

    return {
        'filename': filename,
        'sha256': sha256_hash,
        'md5': md5_hash,
        'file_size': file_size,
        'file_type': ext or 'unknown',
        'risk_score': risk_score,
        'verdict': verdict,
        'findings': findings,
    }


# ── Link Scanner: Phishing Detection ────────────────────────────────────────

BRAND_MISSPELLINGS = {
    'paypal': ['paypa1', 'paypol', 'paipal', 'payp4l', 'payypal', 'paypaI'],
    'google': ['googie', 'gooogle', 'g00gle', 'googel', 'go0gle'],
    'facebook': ['faceb00k', 'faceboook', 'facebok', 'facbook'],
    'microsoft': ['micr0soft', 'mircosoft', 'microsft', 'micros0ft'],
    'apple': ['app1e', 'appie', 'appl3', 'aple'],
    'amazon': ['amaz0n', 'amazom', 'arnazon', 'armazon'],
    'netflix': ['netfIix', 'netfl1x', 'netflex', 'n3tflix'],
    'instagram': ['1nstagram', 'instagran', 'instogram'],
    'twitter': ['tw1tter', 'twtter', 'twiter'],
    'linkedin': ['1inkedin', 'linkedln', 'l1nkedin'],
}

SUSPICIOUS_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz',
    '.club', '.work', '.date', '.loan', '.click', '.link',
    '.racing', '.review', '.stream', '.download', '.win',
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure',
    'banking', 'confirm', 'password', 'credential', 'suspend',
    'unusual', 'alert', 'locked', 'expire', 'wallet', 'prize',
]


def scan_url(url):
    """
    Analyze a URL for phishing indicators.

    Returns dict with risk_score (0-100), verdict, and findings.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    findings = []
    risk_score = 0

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        full_url = url.lower()
    except Exception:
        return {
            'url': url,
            'risk_score': 100,
            'verdict': 'Phishing Detected',
            'findings': [{'type': 'critical', 'message': 'Invalid URL format'}],
        }

    # Check for IP-based domain
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(hostname):
        findings.append({'type': 'critical', 'message': 'IP-based domain detected (common phishing indicator)'})
        risk_score += 30

    # Check for long hostname
    if len(hostname) > 50:
        findings.append({'type': 'warning', 'message': f'Unusually long domain name ({len(hostname)} chars)'})
        risk_score += 15

    # Check for excessive subdomains
    subdomain_count = hostname.count('.') - 1
    if subdomain_count > 3:
        findings.append({'type': 'warning', 'message': f'Excessive subdomains ({subdomain_count + 1} levels)'})
        risk_score += 20

    # Check for suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append({'type': 'warning', 'message': f'Suspicious TLD: {tld}'})
            risk_score += 15
            break

    # Check for brand misspellings
    for brand, misspellings in BRAND_MISSPELLINGS.items():
        for typo in misspellings:
            if typo in hostname:
                findings.append({'type': 'critical', 'message': f'Brand impersonation detected: looks like "{brand}"'})
                risk_score += 40
                break

    # Check for @ symbol in URL (redirects)
    if '@' in url:
        findings.append({'type': 'critical', 'message': '@ symbol in URL (redirect attack)'})
        risk_score += 30

    # Check for special characters
    special_chars = sum(1 for c in hostname if c in '-_~')
    if special_chars > 3:
        findings.append({'type': 'warning', 'message': f'Excessive special characters in domain ({special_chars})'})
        risk_score += 10

    # Check for phishing keywords in path
    keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if len(keyword_hits) >= 2:
        findings.append({'type': 'warning', 'message': f'Phishing keywords in URL: {", ".join(keyword_hits)}'})
        risk_score += 15

    # Check HTTP vs HTTPS
    if parsed.scheme == 'http':
        findings.append({'type': 'info', 'message': 'No SSL/TLS encryption (HTTP only)'})
        risk_score += 10

    # Check for URL shortener patterns
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    if any(s in hostname for s in shorteners):
        findings.append({'type': 'warning', 'message': 'URL shortener detected (may hide true destination)'})
        risk_score += 15

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        verdict = 'Phishing Detected'
    elif risk_score >= 25:
        verdict = 'Suspicious'
    else:
        verdict = 'Safe'

    if not findings:
        findings.append({'type': 'info', 'message': 'No suspicious indicators found'})

    return {
        'url': url,
        'hostname': hostname,
        'risk_score': risk_score,
        'verdict': verdict,
        'findings': findings,
        'ssl': parsed.scheme == 'https',
    }


# ── App Vetter: Vulnerability Scanner ───────────────────────────────────────

VULNERABILITY_PATTERNS = [
    {
        'id': 'VULN-001',
        'name': 'Hardcoded Password',
        'severity': 'Critical',
        'pattern': r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{3,}["\']',
        'description': 'Hardcoded credential or secret found in source code.',
        'recommendation': 'Use environment variables or a secrets manager.',
    },
    {
        'id': 'VULN-002',
        'name': 'Weak Hashing (MD5)',
        'severity': 'High',
        'pattern': r'(?:md5|MD5)\s*\(',
        'description': 'MD5 is cryptographically broken and unsuitable for security.',
        'recommendation': 'Use SHA-256 or bcrypt for hashing.',
    },
    {
        'id': 'VULN-003',
        'name': 'Weak Hashing (SHA1)',
        'severity': 'High',
        'pattern': r'(?:sha1|SHA1)\s*\(',
        'description': 'SHA1 has known collision vulnerabilities.',
        'recommendation': 'Use SHA-256 or stronger alternatives.',
    },
    {
        'id': 'VULN-004',
        'name': 'Use of eval()',
        'severity': 'Critical',
        'pattern': r'\beval\s*\(',
        'description': 'eval() can execute arbitrary code, leading to injection attacks.',
        'recommendation': 'Use safe alternatives like ast.literal_eval() or proper parsing.',
    },
    {
        'id': 'VULN-005',
        'name': 'Use of exec()',
        'severity': 'Critical',
        'pattern': r'\bexec\s*\(',
        'description': 'exec() can execute arbitrary code.',
        'recommendation': 'Avoid dynamic code execution. Use structured approaches.',
    },
    {
        'id': 'VULN-006',
        'name': 'OS Command Injection',
        'severity': 'Critical',
        'pattern': r'os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True',
        'description': 'Direct OS command execution may allow command injection.',
        'recommendation': 'Use subprocess with shell=False and proper argument lists.',
    },
    {
        'id': 'VULN-007',
        'name': 'SQL Injection Risk',
        'severity': 'Critical',
        'pattern': r'(?:execute|cursor\.execute)\s*\(\s*["\'].*?%[sd]|(?:execute|cursor\.execute)\s*\(\s*f["\']',
        'description': 'String formatting in SQL queries allows injection attacks.',
        'recommendation': 'Use parameterized queries with placeholders.',
    },
    {
        'id': 'VULN-008',
        'name': 'Debug Mode Enabled',
        'severity': 'Medium',
        'pattern': r'debug\s*=\s*True|DEBUG\s*=\s*True',
        'description': 'Debug mode should be disabled in production.',
        'recommendation': 'Set debug=False for production deployments.',
    },
    {
        'id': 'VULN-009',
        'name': 'Insecure Random',
        'severity': 'Medium',
        'pattern': r'import\s+random\b(?!.*secrets)',
        'description': 'The random module is not suitable for security purposes.',
        'recommendation': 'Use the secrets module for security-sensitive randomness.',
    },
    {
        'id': 'VULN-010',
        'name': 'Pickle Deserialization',
        'severity': 'High',
        'pattern': r'pickle\.loads?\s*\(|pickle\.Unpickler',
        'description': 'Pickle deserialization of untrusted data can execute arbitrary code.',
        'recommendation': 'Use JSON or other safe serialization formats for untrusted data.',
    },
    {
        'id': 'VULN-011',
        'name': 'Disabled SSL Verification',
        'severity': 'High',
        'pattern': r'verify\s*=\s*False',
        'description': 'Disabling SSL verification exposes to man-in-the-middle attacks.',
        'recommendation': 'Always verify SSL certificates in production.',
    },
    {
        'id': 'VULN-012',
        'name': 'Binding to All Interfaces',
        'severity': 'Medium',
        'pattern': r'host\s*=\s*["\']0\.0\.0\.0["\']',
        'description': 'Binding to 0.0.0.0 exposes the service to all network interfaces.',
        'recommendation': 'Bind to 127.0.0.1 for local-only access.',
    },
]


def scan_code(code_text):
    """
    Scan source code for security vulnerabilities.

    Returns dict with vulnerability count, overall risk, and detailed findings.
    """
    findings = []
    lines = code_text.split('\n')

    for vuln in VULNERABILITY_PATTERNS:
        pattern = re.compile(vuln['pattern'], re.IGNORECASE)
        for line_num, line in enumerate(lines, 1):
            if pattern.search(line):
                findings.append({
                    'id': vuln['id'],
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'line': line_num,
                    'code': line.strip()[:100],
                    'description': vuln['description'],
                    'recommendation': vuln['recommendation'],
                })

    # Calculate risk score
    severity_scores = {'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 3}
    total_score = sum(severity_scores.get(f['severity'], 0) for f in findings)
    risk_score = min(total_score, 100)

    # Count by severity
    severity_counts = {}
    for f in findings:
        sev = f['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if risk_score >= 50:
        verdict = 'High Risk'
    elif risk_score >= 25:
        verdict = 'Medium Risk'
    elif findings:
        verdict = 'Low Risk'
    else:
        verdict = 'Clean'

    return {
        'total_vulnerabilities': len(findings),
        'risk_score': risk_score,
        'verdict': verdict,
        'severity_counts': severity_counts,
        'findings': findings,
        'lines_scanned': len(lines),
    }
