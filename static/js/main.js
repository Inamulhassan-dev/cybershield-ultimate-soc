/**
 * CyberShield Ultimate - Main JS
 * Live log feed, system status polling, terminal emulator
 */

// ── Live Log Feed ──────────────────────────────────────────
const logFeed = document.getElementById('logFeed');
const MAX_LOGS = 80;

async function fetchLogs() {
    try {
        const res = await fetch('/api/logs');
        const data = await res.json();
        const logs = data.logs || [];

        logs.forEach(log => {
            const entry = document.createElement('div');
            let entryClass = 'info';
            const msg = log.message || '';

            if (msg.includes('[CRITICAL]')) entryClass = 'critical';
            else if (msg.includes('[ALERT]')) entryClass = 'alert';
            else if (msg.includes('[WARN]')) entryClass = 'warning';

            entry.className = `log-entry ${entryClass}`;
            entry.innerHTML = `<span class="log-time">${log.timestamp || '--:--:--'}</span><span>${msg}</span>`;
            logFeed.appendChild(entry);
        });

        // Trim old entries
        while (logFeed.children.length > MAX_LOGS) {
            logFeed.removeChild(logFeed.firstChild);
        }

        // Auto-scroll
        logFeed.scrollTop = logFeed.scrollHeight;
    } catch (e) {
        console.error('Log feed error:', e);
    }
}

// ── System Status Polling ──────────────────────────────────
async function updateSystemStatus() {
    try {
        const res = await fetch('/api/system-status');
        const data = await res.json();

        const badge = document.getElementById('systemStatusBadge');
        const dot = document.getElementById('statusDot');
        const text = document.getElementById('statusText');
        const fill = document.getElementById('threatLevelFill');
        const levelText = document.getElementById('threatLevelText');

        if (data.status === 'SECURE') {
            badge.className = 'status-badge secure';
            dot.className = 'status-dot green';
            text.textContent = 'SYSTEM SECURE';
        } else {
            badge.className = 'status-badge attack';
            dot.className = 'status-dot red';
            text.textContent = 'UNDER ATTACK';
        }

        const level = (data.threat_level || 'LOW').toLowerCase();
        fill.className = `threat-level-fill ${level}`;
        levelText.textContent = data.threat_level || 'LOW';
    } catch (e) {
        console.error('Status update error:', e);
    }
}

// ── System Resource Bars ───────────────────────────────────
async function updateSidebarResources() {
    try {
        const res = await fetch('/api/system-info');
        const data = await res.json();

        const cpuBar = document.getElementById('cpuBar');
        const memBar = document.getElementById('memBar');
        const cpuText = document.getElementById('sidebarCpu');
        const memText = document.getElementById('sidebarMem');

        if (cpuBar) {
            cpuBar.style.width = data.cpu_percent + '%';
            cpuBar.style.background = data.cpu_percent > 80 ? 'var(--accent-red)' : 'var(--accent-cyan)';
        }
        if (memBar) {
            memBar.style.width = data.memory_percent + '%';
            memBar.style.background = data.memory_percent > 80 ? 'var(--accent-red)' : 'var(--accent-purple)';
        }
        if (cpuText) cpuText.textContent = data.cpu_percent?.toFixed(1) + '%';
        if (memText) memText.textContent = data.memory_percent?.toFixed(1) + '%';
    } catch (e) {
        console.error('Resource bar error:', e);
    }
}

// ── Mini Terminal ──────────────────────────────────────────
const terminalInput = document.getElementById('terminalInput');
const terminalBody = document.getElementById('terminalBody');

const TERMINAL_COMMANDS = {
    help: () => `Available commands:
  status    - System security status
  threats   - Active threat count
  scan      - Quick network scan
  clear     - Clear terminal
  uptime    - System uptime
  whoami    - Current user info
  version   - CyberShield version`,
    status: () => 'System Status: OPERATIONAL | Firewall: ACTIVE | IDS: ONLINE',
    threats: () => `Active threats detected: ${Math.floor(Math.random() * 5)} | Blocked today: ${Math.floor(Math.random() * 200)}`,
    scan: () => `Scanning local network...\n  > 192.168.1.1 - Gateway [ONLINE]\n  > 192.168.1.${Math.floor(10 + Math.random() * 240)} - Unknown device [FLAGGED]\n  > Scan complete. 1 suspicious device found.`,
    clear: () => '__CLEAR__',
    uptime: () => `System uptime: ${Math.floor(Math.random() * 30)}d ${Math.floor(Math.random() * 24)}h ${Math.floor(Math.random() * 60)}m`,
    whoami: () => 'operator@cybershield-ultimate [ADMIN]',
    version: () => 'CyberShield Ultimate v2.0.0 | AI Engine v1.3 | Build 2026.03',
};

if (terminalInput) {
    terminalInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            const cmd = this.value.trim().toLowerCase();
            if (!cmd) return;

            // Echo command
            const cmdLine = document.createElement('div');
            cmdLine.style.color = 'var(--accent-cyan)';
            cmdLine.textContent = `$> ${cmd}`;
            terminalBody.appendChild(cmdLine);

            // Process
            const handler = TERMINAL_COMMANDS[cmd];
            if (handler) {
                const result = handler();
                if (result === '__CLEAR__') {
                    terminalBody.innerHTML = '<div>> Terminal cleared</div>';
                } else {
                    result.split('\n').forEach(line => {
                        const el = document.createElement('div');
                        el.textContent = line;
                        terminalBody.appendChild(el);
                    });
                }
            } else {
                const el = document.createElement('div');
                el.style.color = 'var(--accent-red)';
                el.textContent = `Command not found: ${cmd}. Type 'help' for available commands.`;
                terminalBody.appendChild(el);
            }

            this.value = '';
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }
    });
}

// ── Init ───────────────────────────────────────────────────
fetchLogs();
updateSystemStatus();
updateSidebarResources();

setInterval(fetchLogs, 10000);
setInterval(updateSystemStatus, 15000);
setInterval(updateSidebarResources, 15000);
