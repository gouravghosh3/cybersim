/**
 * Network Traffic Analysis Simulation
 * Analyze packet captures to identify suspicious activity
 */

const NetworkAnalysisSimulation = {
    packets: [],
    flaggedPackets: new Set(),
    maliciousPackets: new Set(),

    scenarios: [
        {
            id: 'c2-beacon',
            title: 'Command & Control Detection',
            description: 'Analyze network traffic to identify Command & Control (C2) beacon activity from a potentially compromised endpoint.',
            packets: [
                { id: 1, time: '14:30:01', src: '192.168.1.45', dst: '8.8.8.8', port: 53, protocol: 'DNS', size: 64, info: 'Standard query A www.google.com', malicious: false },
                { id: 2, time: '14:30:02', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1420, info: 'TLS Client Hello to unknown host', malicious: true },
                { id: 3, time: '14:30:15', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1380, info: 'TLS Application Data (encrypted)', malicious: true },
                { id: 4, time: '14:30:28', src: '192.168.1.100', dst: '52.84.123.45', port: 443, protocol: 'HTTPS', size: 980, info: 'TLS Client Hello to amazonaws.com', malicious: false },
                { id: 5, time: '14:30:30', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1395, info: 'TLS Application Data (encrypted)', malicious: true },
                { id: 6, time: '14:30:45', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1410, info: 'TLS Application Data (encrypted)', malicious: true },
                { id: 7, time: '14:31:00', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1388, info: 'TLS Application Data (encrypted)', malicious: true },
                { id: 8, time: '14:31:05', src: '192.168.1.75', dst: '142.250.185.14', port: 443, protocol: 'HTTPS', size: 1200, info: 'TLS Client Hello to google.com', malicious: false },
                { id: 9, time: '14:31:15', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1402, info: 'TLS Application Data (encrypted)', malicious: true },
                { id: 10, time: '14:31:30', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1375, info: 'TLS Application Data (encrypted)', malicious: true },
                { id: 11, time: '14:31:45', src: '192.168.1.50', dst: '151.101.1.140', port: 443, protocol: 'HTTPS', size: 856, info: 'TLS Client Hello to reddit.com', malicious: false },
                { id: 12, time: '14:32:00', src: '192.168.1.45', dst: '185.234.72.19', port: 443, protocol: 'HTTPS', size: 1398, info: 'TLS Application Data (encrypted)', malicious: true }
            ],
            hints: [
                'Look for repeated connections to the same external IP at regular intervals',
                'C2 beacons often have consistent packet sizes and timing patterns',
                'Unknown or suspicious destination IPs warrant investigation'
            ]
        },
        {
            id: 'data-exfil',
            title: 'Data Exfiltration Detection',
            description: 'Identify potential data exfiltration attempts by analyzing outbound network traffic patterns.',
            packets: [
                { id: 1, time: '09:15:00', src: '192.168.1.25', dst: '192.168.1.5', port: 445, protocol: 'SMB', size: 1460, info: 'Read request for \\\\FileServer\\HR\\employee_data.xlsx', malicious: false },
                { id: 2, time: '09:15:02', src: '192.168.1.25', dst: '104.18.32.68', port: 443, protocol: 'HTTPS', size: 8240, info: 'Large outbound transfer to file.io', malicious: true },
                { id: 3, time: '09:15:05', src: '192.168.1.25', dst: '104.18.32.68', port: 443, protocol: 'HTTPS', size: 12480, info: 'Continuation - file.io upload', malicious: true },
                { id: 4, time: '09:15:08', src: '192.168.1.25', dst: '104.18.32.68', port: 443, protocol: 'HTTPS', size: 9650, info: 'Continuation - file.io upload', malicious: true },
                { id: 5, time: '09:15:30', src: '192.168.1.80', dst: '13.107.42.14', port: 443, protocol: 'HTTPS', size: 1240, info: 'TLS Client Hello to outlook.office365.com', malicious: false },
                { id: 6, time: '09:16:00', src: '192.168.1.25', dst: '192.168.1.5', port: 445, protocol: 'SMB', size: 1460, info: 'Read request for \\\\FileServer\\Finance\\salaries_2024.csv', malicious: false },
                { id: 7, time: '09:16:03', src: '192.168.1.25', dst: '104.18.32.68', port: 443, protocol: 'HTTPS', size: 15200, info: 'Large outbound transfer to file.io', malicious: true },
                { id: 8, time: '09:16:06', src: '192.168.1.25', dst: '104.18.32.68', port: 443, protocol: 'HTTPS', size: 11800, info: 'Continuation - file.io upload', malicious: true },
                { id: 9, time: '09:16:30', src: '192.168.1.60', dst: '20.190.128.1', port: 443, protocol: 'HTTPS', size: 980, info: 'Normal OneDrive sync activity', malicious: false },
                { id: 10, time: '09:17:00', src: '192.168.1.25', dst: '8.8.8.8', port: 53, protocol: 'DNS', size: 256, info: 'DNS TXT query for d2hhdGV2ZXI.suspicious-domain.tk', malicious: true },
                { id: 11, time: '09:17:02', src: '8.8.8.8', dst: '192.168.1.25', port: 53, protocol: 'DNS', size: 512, info: 'DNS TXT response (unusually large)', malicious: true },
                { id: 12, time: '09:17:30', src: '192.168.1.40', dst: '140.82.121.4', port: 443, protocol: 'HTTPS', size: 1100, info: 'TLS Client Hello to github.com', malicious: false }
            ],
            hints: [
                'Watch for large outbound transfers to file sharing services',
                'DNS tunneling uses unusually large DNS responses',
                'Pattern: internal file access followed immediately by external upload'
            ]
        }
    ],

    currentScenario: null,

    render() {
        // Fixed scenario for competition fairness (no randomization)
        this.currentScenario = this.scenarios[0];
        this.packets = [...this.currentScenario.packets];
        this.maliciousPackets = new Set(this.packets.filter(p => p.malicious).map(p => p.id));
        this.flaggedPackets = new Set();

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">${this.currentScenario.title}</h2>
                <div class="simulation-timer">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                    <span>${this.packets.length} packets captured</span>
                </div>
            </div>
            
            <div class="simulation-instructions">
                <h4>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="16" x2="12" y2="12"/>
                        <line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                    Analysis Task
                </h4>
                <p>${this.currentScenario.description} Flag all suspicious packets by clicking the flag icon, then submit your findings.</p>
            </div>
            
            <div class="simulation-content">
                <div style="background: #0a0a0a; border-radius: 12px; overflow: hidden; border: 1px solid var(--border-color);">
                    <table class="packet-table">
                        <thead>
                            <tr>
                                <th style="width: 50px;">Flag</th>
                                <th style="width: 80px;">Time</th>
                                <th style="width: 130px;">Source</th>
                                <th style="width: 130px;">Destination</th>
                                <th style="width: 60px;">Port</th>
                                <th style="width: 80px;">Protocol</th>
                                <th style="width: 70px;">Size</th>
                                <th>Info</th>
                            </tr>
                        </thead>
                        <tbody id="packet-tbody">
                            ${this.packets.map(packet => `
                                <tr data-id="${packet.id}" class="${this.flaggedPackets.has(packet.id) ? 'flagged' : ''}">
                                    <td>
                                        <button class="packet-flag ${this.flaggedPackets.has(packet.id) ? 'active' : ''}" onclick="NetworkAnalysisSimulation.toggleFlag(${packet.id})">
                                            <svg viewBox="0 0 24 24" fill="${this.flaggedPackets.has(packet.id) ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" width="16" height="16">
                                                <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>
                                                <line x1="4" y1="22" x2="4" y2="15"/>
                                            </svg>
                                        </button>
                                    </td>
                                    <td>${packet.time}</td>
                                    <td>${packet.src}</td>
                                    <td>${packet.dst}</td>
                                    <td>${packet.port}</td>
                                    <td><span class="log-level ${packet.protocol === 'DNS' ? 'info' : 'warning'}">${packet.protocol}</span></td>
                                    <td>${packet.size}</td>
                                    <td>${packet.info}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                
                <div style="margin-top: 20px; padding: 16px; background: var(--bg-glass); border-radius: 8px; border: 1px solid var(--border-color);">
                    <h4 style="color: var(--green); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <circle cx="12" cy="12" r="10"/>
                            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        Analyst Hints
                    </h4>
                    <ul style="color: var(--text-secondary); font-size: 0.9rem; margin-left: 20px;">
                        ${this.currentScenario.hints.map(hint => `<li style="margin-bottom: 6px;">${hint}</li>`).join('')}
                    </ul>
                </div>
            </div>
            
            <div class="simulation-actions">
                <button class="btn btn-outline" onclick="exitSimulation()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="19" y1="12" x2="5" y2="12"/>
                        <polyline points="12 19 5 12 12 5"/>
                    </svg>
                    Exit
                </button>
                <div>
                    <span id="flagged-count" style="margin-right: 16px; color: var(--text-secondary);">0 packets flagged</span>
                    <button class="btn btn-primary" onclick="NetworkAnalysisSimulation.submit()">
                        Submit Analysis
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9 11 12 14 22 4"/>
                            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;
    },

    init() {
        // Nothing special needed
    },

    toggleFlag(id) {
        const row = document.querySelector(`tr[data-id="${id}"]`);
        const btn = row.querySelector('.packet-flag');
        const svg = btn.querySelector('svg');

        if (this.flaggedPackets.has(id)) {
            this.flaggedPackets.delete(id);
            row.classList.remove('flagged');
            btn.classList.remove('active');
            svg.setAttribute('fill', 'none');
        } else {
            this.flaggedPackets.add(id);
            row.classList.add('flagged');
            btn.classList.add('active');
            svg.setAttribute('fill', 'currentColor');
        }

        document.getElementById('flagged-count').textContent = `${this.flaggedPackets.size} packets flagged`;
    },

    submit() {
        let correctHits = 0;
        let falsePositives = 0;
        let missedThreats = 0;
        const feedback = [];

        // Check flagged packets
        this.flaggedPackets.forEach(id => {
            const packet = this.packets.find(p => p.id === id);
            if (this.maliciousPackets.has(id)) {
                correctHits++;
                feedback.push({
                    correct: true,
                    title: `✓ Correctly flagged: ${packet.src} → ${packet.dst}`,
                    explanation: `Good catch! ${this.getExplanation(packet)}`
                });
            } else {
                falsePositives++;
                feedback.push({
                    correct: false,
                    title: `✗ False positive: ${packet.src} → ${packet.dst}`,
                    explanation: `This is normal traffic: ${packet.info}`
                });
            }
        });

        // Check missed threats
        this.maliciousPackets.forEach(id => {
            if (!this.flaggedPackets.has(id)) {
                missedThreats++;
                const packet = this.packets.find(p => p.id === id);
                feedback.push({
                    correct: false,
                    title: `⚠ Missed threat: ${packet.src} → ${packet.dst}`,
                    explanation: `This packet shows ${this.getExplanation(packet)}`
                });
            }
        });

        // Visual feedback
        this.packets.forEach(packet => {
            const row = document.querySelector(`tr[data-id="${packet.id}"]`);
            if (packet.malicious && this.flaggedPackets.has(packet.id)) {
                row.style.background = 'rgba(0, 255, 136, 0.1)';
                row.style.borderLeft = '3px solid var(--green)';
            } else if (packet.malicious && !this.flaggedPackets.has(packet.id)) {
                row.style.background = 'rgba(255, 217, 61, 0.1)';
                row.style.borderLeft = '3px solid var(--yellow)';
            } else if (!packet.malicious && this.flaggedPackets.has(packet.id)) {
                row.style.background = 'rgba(255, 56, 96, 0.1)';
                row.style.borderLeft = '3px solid var(--red)';
            }
        });

        // Calculate score
        const maxScore = 600;
        const baseScore = (correctHits / this.maliciousPackets.size) * maxScore;
        const penalties = (falsePositives * 40) + (missedThreats * 30);
        const finalScore = Math.max(0, Math.round(baseScore - penalties));

        setTimeout(() => {
            completeSimulation('network-analysis', finalScore, maxScore, feedback);
        }, 1500);
    },

    getExplanation(packet) {
        if (packet.info.includes('unknown host')) return 'connection to unregistered/suspicious external IP';
        if (packet.info.includes('file.io')) return 'upload to anonymous file sharing service (potential data exfiltration)';
        if (packet.info.includes('TXT query') || packet.info.includes('TXT response')) return 'potential DNS tunneling activity';
        if (packet.info.includes('185.234.72.19')) return 'regular beaconing pattern to suspicious external IP (C2 indicator)';
        if (packet.info.includes('beacon') || packet.dst === '185.234.72.19') return 'periodic communication pattern typical of C2 beacons';
        return 'suspicious network activity warranting investigation';
    }
};

// Export for global access
window.NetworkAnalysisSimulation = NetworkAnalysisSimulation;
