/**
 * CyberShield Ultimate - Network JS
 * Network topology graph (Canvas) + Threat radar
 */

// ── Network Topology ───────────────────────────────────────
const topoCanvas = document.getElementById('topologyCanvas');
let topoCtx, topoNodes, topoAnimId;

if (topoCanvas) {
    topoCtx = topoCanvas.getContext('2d');
    resizeTopoCanvas();
    window.addEventListener('resize', resizeTopoCanvas);
    initTopology();
}

function resizeTopoCanvas() {
    if (!topoCanvas) return;
    const rect = topoCanvas.parentElement.getBoundingClientRect();
    topoCanvas.width = rect.width;
    topoCanvas.height = 350;
}

function initTopology() {
    const w = topoCanvas.width;
    const h = topoCanvas.height;

    // Create nodes
    const nodeNames = [
        { name: 'Firewall', type: 'security', icon: '🛡️' },
        { name: 'Router', type: 'network', icon: '📡' },
        { name: 'Web Server', type: 'server', icon: '🖥️' },
        { name: 'DB Server', type: 'server', icon: '💾' },
        { name: 'API Gateway', type: 'network', icon: '🔗' },
        { name: 'User PC-1', type: 'client', icon: '💻' },
        { name: 'User PC-2', type: 'client', icon: '💻' },
        { name: 'IoT Device', type: 'iot', icon: '📱' },
        { name: 'Cloud CDN', type: 'cloud', icon: '☁️' },
        { name: 'Mail Server', type: 'server', icon: '📧' },
        { name: 'DNS', type: 'network', icon: '🌐' },
        { name: 'Attacker?', type: 'threat', icon: '⚠️' },
    ];

    topoNodes = nodeNames.map((n, i) => {
        const angle = (i / nodeNames.length) * Math.PI * 2;
        const radiusX = w * 0.35;
        const radiusY = h * 0.35;
        // Place in elliptical pattern with some randomness
        let x, y;
        if (i === 0) {
            x = w / 2; y = h * 0.15; // Firewall at top
        } else if (n.type === 'threat') {
            x = w * 0.85; y = h * 0.85; // Attacker at bottom right
        } else {
            x = w / 2 + Math.cos(angle) * radiusX * (0.6 + Math.random() * 0.4);
            y = h / 2 + Math.sin(angle) * radiusY * (0.6 + Math.random() * 0.4);
        }
        return {
            ...n,
            x: Math.max(50, Math.min(w - 50, x)),
            y: Math.max(30, Math.min(h - 30, y)),
            radius: n.type === 'security' ? 22 : n.type === 'threat' ? 20 : 16,
            pulse: Math.random() * Math.PI * 2,
        };
    });

    // Connections
    topoNodes.connections = [
        [0, 1], [1, 2], [1, 3], [1, 4], [1, 10],
        [2, 4], [3, 4], [4, 8], [4, 9],
        [1, 5], [1, 6], [1, 7],
        [11, 1], // Attack line
        [11, 2], // Attack line
    ];

    animateTopology();
}

function animateTopology() {
    if (!topoCtx || !topoNodes) return;

    const w = topoCanvas.width;
    const h = topoCanvas.height;
    topoCtx.clearRect(0, 0, w, h);

    const time = Date.now() / 1000;

    // Draw connections
    topoNodes.connections.forEach(([from, to]) => {
        const a = topoNodes[from];
        const b = topoNodes[to];
        const isAttack = a.type === 'threat' || b.type === 'threat';

        topoCtx.beginPath();
        topoCtx.moveTo(a.x, a.y);
        topoCtx.lineTo(b.x, b.y);

        if (isAttack) {
            topoCtx.strokeStyle = `rgba(255, 0, 60, ${0.4 + Math.sin(time * 3) * 0.3})`;
            topoCtx.lineWidth = 2;
            topoCtx.setLineDash([6, 4]);
        } else {
            topoCtx.strokeStyle = 'rgba(0, 247, 255, 0.15)';
            topoCtx.lineWidth = 1;
            topoCtx.setLineDash([]);
        }
        topoCtx.stroke();
        topoCtx.setLineDash([]);

        // Data packet animation on normal lines
        if (!isAttack) {
            const t = (time * 0.5 + from * 0.3) % 1;
            const px = a.x + (b.x - a.x) * t;
            const py = a.y + (b.y - a.y) * t;
            topoCtx.beginPath();
            topoCtx.arc(px, py, 2, 0, Math.PI * 2);
            topoCtx.fillStyle = 'rgba(0, 247, 255, 0.6)';
            topoCtx.fill();
        } else {
            // Red attack packets
            const t = (time * 0.8 + from * 0.2) % 1;
            const px = a.x + (b.x - a.x) * t;
            const py = a.y + (b.y - a.y) * t;
            topoCtx.beginPath();
            topoCtx.arc(px, py, 3, 0, Math.PI * 2);
            topoCtx.fillStyle = 'rgba(255, 0, 60, 0.8)';
            topoCtx.fill();
        }
    });

    // Draw nodes
    topoNodes.forEach((node, i) => {
        const pulseScale = 1 + Math.sin(time * 2 + node.pulse) * 0.08;
        const r = node.radius * pulseScale;

        // Glow
        const gradient = topoCtx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 2);
        if (node.type === 'threat') {
            gradient.addColorStop(0, 'rgba(255, 0, 60, 0.2)');
            gradient.addColorStop(1, 'rgba(255, 0, 60, 0)');
        } else if (node.type === 'security') {
            gradient.addColorStop(0, 'rgba(0, 255, 136, 0.2)');
            gradient.addColorStop(1, 'rgba(0, 255, 136, 0)');
        } else {
            gradient.addColorStop(0, 'rgba(0, 247, 255, 0.1)');
            gradient.addColorStop(1, 'rgba(0, 247, 255, 0)');
        }
        topoCtx.beginPath();
        topoCtx.arc(node.x, node.y, r * 2, 0, Math.PI * 2);
        topoCtx.fillStyle = gradient;
        topoCtx.fill();

        // Node circle
        topoCtx.beginPath();
        topoCtx.arc(node.x, node.y, r, 0, Math.PI * 2);
        topoCtx.fillStyle = node.type === 'threat' ? 'rgba(255, 0, 60, 0.2)' :
                            node.type === 'security' ? 'rgba(0, 255, 136, 0.15)' :
                            'rgba(0, 247, 255, 0.1)';
        topoCtx.fill();
        topoCtx.strokeStyle = node.type === 'threat' ? '#ff003c' :
                              node.type === 'security' ? '#00ff88' :
                              'rgba(0, 247, 255, 0.4)';
        topoCtx.lineWidth = 1.5;
        topoCtx.stroke();

        // Icon
        topoCtx.font = `${r * 0.9}px sans-serif`;
        topoCtx.textAlign = 'center';
        topoCtx.textBaseline = 'middle';
        topoCtx.fillText(node.icon, node.x, node.y);

        // Label
        topoCtx.font = "10px 'Share Tech Mono', monospace";
        topoCtx.fillStyle = node.type === 'threat' ? '#ff003c' :
                            node.type === 'security' ? '#00ff88' : '#8892b0';
        topoCtx.fillText(node.name, node.x, node.y + r + 14);
    });

    topoAnimId = requestAnimationFrame(animateTopology);
}

// ── Threat Radar ───────────────────────────────────────────
const radarCanvas = document.getElementById('radarCanvas');
let radarCtx, radarAnimId;

if (radarCanvas) {
    radarCtx = radarCanvas.getContext('2d');
    radarCanvas.width = 280;
    radarCanvas.height = 280;
    animateRadar();
}

let radarBlips = [];

// Expose function to update blips from actual real-time network traffic
window.updateRadarBlips = function(trafficData) {
    // Generate blips from real network packets
    radarBlips = (trafficData || []).map(t => {
        const isAttack = t.is_threat || (t.label && t.label !== 'Normal');
        return {
            angle: Math.random() * Math.PI * 2,
            dist: 0.2 + Math.random() * 0.7,
            type: isAttack ? 'threat' : 'normal',
            pulse: Math.random() * Math.PI * 2,
        };
    });
};

function animateRadar() {
    if (!radarCtx) return;

    const w = radarCanvas.width;
    const h = radarCanvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const maxR = Math.min(cx, cy) - 10;
    const time = Date.now() / 1000;
    const sweepAngle = (time * 0.8) % (Math.PI * 2);

    radarCtx.clearRect(0, 0, w, h);

    // Concentric circles
    for (let i = 1; i <= 4; i++) {
        const r = maxR * (i / 4);
        radarCtx.beginPath();
        radarCtx.arc(cx, cy, r, 0, Math.PI * 2);
        radarCtx.strokeStyle = 'rgba(0, 247, 255, 0.1)';
        radarCtx.lineWidth = 1;
        radarCtx.stroke();
    }

    // Cross lines
    radarCtx.beginPath();
    radarCtx.moveTo(cx - maxR, cy); radarCtx.lineTo(cx + maxR, cy);
    radarCtx.moveTo(cx, cy - maxR); radarCtx.lineTo(cx, cy + maxR);
    radarCtx.strokeStyle = 'rgba(0, 247, 255, 0.08)';
    radarCtx.stroke();

    // Simple, robust sweep fill so it doesn't crash the canvas renderer
    radarCtx.beginPath();
    radarCtx.moveTo(cx, cy);
    radarCtx.arc(cx, cy, maxR, sweepAngle, sweepAngle + Math.PI * 0.2);
    radarCtx.closePath();
    radarCtx.fillStyle = 'rgba(0, 247, 255, 0.08)';
    radarCtx.fill();

    // Sweep line
    radarCtx.beginPath();
    radarCtx.moveTo(cx, cy);
    radarCtx.lineTo(cx + Math.cos(sweepAngle) * maxR, cy + Math.sin(sweepAngle) * maxR);
    radarCtx.strokeStyle = 'rgba(0, 247, 255, 0.5)';
    radarCtx.lineWidth = 1.5;
    radarCtx.stroke();

    // Blips
    try {
        radarBlips.forEach(blip => {
            try {
                const bx = cx + Math.cos(blip.angle) * maxR * blip.dist;
                const by = cy + Math.sin(blip.angle) * maxR * blip.dist;
                const pulseR = Math.max(0.1, 4 + Math.sin(time * 3 + blip.pulse) * 1.5);

                // Check if sweep is near
                let angleDiff = Math.abs(sweepAngle - blip.angle) % (Math.PI * 2);
                if (angleDiff > Math.PI) angleDiff = Math.PI * 2 - angleDiff;
                const brightness = angleDiff < 0.5 ? 1 : Math.max(0.2, 1 - angleDiff * 0.3);

                const color = blip.type === 'threat' ? `rgba(255, 0, 60, ${brightness})` : `rgba(0, 247, 255, ${brightness * 0.7})`;

                // Glow
                radarCtx.beginPath();
                radarCtx.arc(bx, by, pulseR * 3, 0, Math.PI * 2);
                radarCtx.fillStyle = blip.type === 'threat' ? `rgba(255, 0, 60, ${brightness * 0.15})` : `rgba(0, 247, 255, ${brightness * 0.1})`;
                radarCtx.fill();

                // Dot
                radarCtx.beginPath();
                radarCtx.arc(bx, by, pulseR, 0, Math.PI * 2);
                radarCtx.fillStyle = color;
                radarCtx.fill();
            } catch (innerErr) {
                // Ignore single blip error
            }
        });

        // Center dot
        radarCtx.beginPath();
        radarCtx.arc(cx, cy, 4, 0, Math.PI * 2);
        radarCtx.fillStyle = '#00f7ff';
        radarCtx.fill();

    } catch (e) {
        console.error("Radar draw error:", e);
    }

    // Labels
    radarCtx.font = "9px 'Share Tech Mono', monospace";
    radarCtx.fillStyle = 'rgba(0, 247, 255, 0.4)';
    radarCtx.textAlign = 'center';
    radarCtx.fillText('N', cx, cy - maxR - 4);
    radarCtx.fillText('S', cx, cy + maxR + 12);
    radarCtx.fillText('E', cx + maxR + 8, cy + 4);
    radarCtx.fillText('W', cx - maxR - 8, cy + 4);

    radarAnimId = requestAnimationFrame(animateRadar);
}

// Optional: slowly rotate real blips to make it feel dynamic
setInterval(() => {
    if (radarBlips.length > 0) {
        radarBlips.forEach(b => {
            b.angle = (b.angle + 0.02) % (Math.PI * 2);
        });
    }
}, 100);
