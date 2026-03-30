/**
 * CyberShield Ultimate - Scanner JS
 * Shared utilities for file scanning, URL scanning, and code analysis.
 */

// ── Utility: Format bytes ─────────────────────────────────
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ── Utility: Animate risk meter ───────────────────────────
function animateRiskMeter(circleId, valueId, score) {
    const circle = document.getElementById(circleId);
    const value = document.getElementById(valueId);
    if (!circle || !value) return;

    const targetOffset = 314 - (314 * score / 100);
    const color = score < 25 ? 'var(--accent-green)' :
                  score < 50 ? 'var(--accent-yellow)' : 'var(--accent-red)';

    // Animate
    let current = 0;
    const step = score / 30;
    const interval = setInterval(() => {
        current = Math.min(current + step, score);
        const offset = 314 - (314 * current / 100);
        circle.style.strokeDashoffset = offset;
        circle.style.stroke = color;
        value.textContent = Math.round(current);
        value.style.color = color;

        if (current >= score) clearInterval(interval);
    }, 20);
}

// ── Utility: Escape HTML ──────────────────────────────────
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ── Utility: Show notification toast ──────────────────────
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 24px;
        border-radius: 8px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 13px;
        z-index: 10000;
        animation: logSlide 0.3s ease;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    `;

    if (type === 'success') {
        toast.style.background = 'rgba(0, 255, 136, 0.15)';
        toast.style.color = '#00ff88';
        toast.style.border = '1px solid rgba(0, 255, 136, 0.3)';
    } else if (type === 'error') {
        toast.style.background = 'rgba(255, 0, 60, 0.15)';
        toast.style.color = '#ff003c';
        toast.style.border = '1px solid rgba(255, 0, 60, 0.3)';
    } else {
        toast.style.background = 'rgba(0, 247, 255, 0.15)';
        toast.style.color = '#00f7ff';
        toast.style.border = '1px solid rgba(0, 247, 255, 0.3)';
    }

    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
