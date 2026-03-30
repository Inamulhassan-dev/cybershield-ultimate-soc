/**
 * CyberShield Ultimate - Charts JS
 * Chart.js analytics: traffic line chart + attack pie chart
 */

// ── Traffic Line Chart ─────────────────────────────────────
const trafficCtx = document.getElementById('trafficChart');
let trafficChart = null;

if (trafficCtx) {
    trafficChart = new Chart(trafficCtx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Normal Traffic',
                    data: [],
                    borderColor: '#00f7ff',
                    backgroundColor: 'rgba(0, 247, 255, 0.08)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#00f7ff',
                },
                {
                    label: 'Malicious Traffic',
                    data: [],
                    borderColor: '#ff003c',
                    backgroundColor: 'rgba(255, 0, 60, 0.08)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#ff003c',
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: '#8892b0',
                        font: { family: "'Share Tech Mono'", size: 11 },
                        boxWidth: 12,
                        padding: 12,
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false },
                    ticks: { color: '#4a5568', font: { family: "'Share Tech Mono'", size: 10 }, maxRotation: 0, maxTicksLimit: 8 }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false },
                    ticks: { color: '#4a5568', font: { family: "'Share Tech Mono'", size: 10 } },
                    beginAtZero: true,
                }
            }
        }
    });
}

// ── Attack Pie Chart ───────────────────────────────────────
const pieCtx = document.getElementById('attackPieChart');
let attackPieChart = null;

if (pieCtx) {
    attackPieChart = new Chart(pieCtx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['DDoS', 'SQL Injection', 'Port Scan', 'Brute Force'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(255, 0, 60, 0.8)',
                    'rgba(255, 184, 0, 0.8)',
                    'rgba(168, 85, 247, 0.8)',
                    'rgba(0, 247, 255, 0.8)',
                ],
                borderColor: [
                    'rgba(255, 0, 60, 1)',
                    'rgba(255, 184, 0, 1)',
                    'rgba(168, 85, 247, 1)',
                    'rgba(0, 247, 255, 1)',
                ],
                borderWidth: 1,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#8892b0',
                        font: { family: "'Share Tech Mono'", size: 10 },
                        boxWidth: 10,
                        padding: 8,
                    }
                }
            }
        }
    });
}

// ── Update Charts ──────────────────────────────────────────
async function updateCharts() {
    try {
        const res = await fetch('/api/analytics');
        const data = await res.json();

        if (trafficChart && data.traffic) {
            trafficChart.data.labels = data.traffic.labels;
            trafficChart.data.datasets[0].data = data.traffic.normal;
            trafficChart.data.datasets[1].data = data.traffic.malicious;
            trafficChart.update('none');
        }

        if (attackPieChart && data.attack_distribution) {
            attackPieChart.data.labels = data.attack_distribution.labels;
            attackPieChart.data.datasets[0].data = data.attack_distribution.values;
            attackPieChart.update('none');
        }
    } catch (e) {
        console.error('Chart update error:', e);
    }
}

// Init
updateCharts();
setInterval(updateCharts, 12000);
