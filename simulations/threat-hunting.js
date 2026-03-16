/**
 * Threat Hunting Simulation - Clustering Analysis
 * Identify anomalies by spotting "clusters of one" in network data
 */

const ThreatHuntingSimulation = {
    currentScenario: 0,
    score: 0,
    maxScore: 800,
    results: [],

    scenarios: [
        {
            id: 'windows-update',
            title: 'Suspicious Update Traffic',
            briefing: `Your SIEM detected outbound HTTPS connections from 100 corporate endpoints to update-related destinations over the last hour. Analyze the clustering of destinations to identify potential C2 masquerading as update traffic.`,
            data: [
                { host: 'WKS-FIN-001', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 15420, connections: 3, anomaly: false },
                { host: 'WKS-FIN-002', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 18230, connections: 4, anomaly: false },
                { host: 'WKS-HR-001', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 12100, connections: 2, anomaly: false },
                { host: 'WKS-HR-002', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 16890, connections: 3, anomaly: false },
                { host: 'WKS-IT-001', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 21050, connections: 5, anomaly: false },
                { host: 'WKS-DEV-003', destination: '185.234.72.19', country: 'RU', port: 443, bytes: 847200, connections: 47, anomaly: true },
                { host: 'WKS-MKT-001', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 14200, connections: 3, anomaly: false },
                { host: 'WKS-MKT-002', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 19800, connections: 4, anomaly: false },
                { host: 'WKS-FIN-003', destination: 'download.windowsupdate.com', country: 'US', port: 443, bytes: 25600, connections: 6, anomaly: false },
                { host: 'WKS-IT-002', destination: 'download.windowsupdate.com', country: 'US', port: 443, bytes: 22400, connections: 5, anomaly: false },
                { host: 'WKS-HR-003', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 11200, connections: 2, anomaly: false },
                { host: 'WKS-DEV-001', destination: 'windowsupdate.microsoft.com', country: 'US', port: 443, bytes: 17600, connections: 3, anomaly: false }
            ],
            clusterSummary: {
                'windowsupdate.microsoft.com (US)': 8,
                'download.windowsupdate.com (US)': 2,
                '185.234.72.19 (RU)': 1
            },
            hints: [
                'Look for destinations that don\'t match the expected cluster',
                'Check for unusual country codes or IP addresses vs domain names',
                'High byte counts with many connections may indicate data exfiltration'
            ],
            explanation: 'WKS-DEV-003 is communicating with a raw IP address in Russia instead of a Microsoft domain, with significantly higher data transfer (847KB vs ~15-25KB average) and 47 connections vs 2-6 normal. This "cluster of one" indicates potential C2 or data exfiltration.'
        },
        {
            id: 'dns-queries',
            title: 'DNS Query Analysis',
            briefing: `Analyze DNS query patterns from internal hosts. Most machines query the same set of internal and external resolvers, but threat actors often use DNS tunneling or rogue resolvers for C2 communication.`,
            data: [
                { host: 'SRV-DC-01', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 450, avgResponseSize: 64, anomaly: false },
                { host: 'SRV-DC-02', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 380, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-FIN-001', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 120, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-FIN-002', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 95, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-HR-001', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 88, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-MKT-005', resolver: '8.8.8.8', queryType: 'TXT', queriesPerHour: 2840, avgResponseSize: 512, anomaly: true },
                { host: 'WKS-IT-001', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 156, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-DEV-001', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 210, avgResponseSize: 64, anomaly: false },
                { host: 'SRV-WEB-01', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 520, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-MKT-001', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 72, avgResponseSize: 64, anomaly: false },
                { host: 'WKS-FIN-003', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 105, avgResponseSize: 64, anomaly: false },
                { host: 'SRV-MAIL-01', resolver: '192.168.1.10', queryType: 'A', queriesPerHour: 680, avgResponseSize: 64, anomaly: false }
            ],
            clusterSummary: {
                'Internal Resolver (192.168.1.10) - Type A': 11,
                'External Resolver (8.8.8.8) - Type TXT': 1
            },
            hints: [
                'Corporate policy requires all DNS to go through internal resolvers',
                'TXT queries with large response sizes may indicate DNS tunneling',
                'Unusually high query rates are suspicious'
            ],
            explanation: 'WKS-MKT-005 is using an external resolver (8.8.8.8) instead of the corporate resolver, making TXT queries (not normal A records), with 2840 queries/hour (vs 72-680 normal) and 512-byte responses (vs 64 normal). This pattern strongly suggests DNS tunneling for data exfiltration or C2.'
        },
        {
            id: 'login-times',
            title: 'Authentication Time Analysis',
            briefing: `Review VPN authentication times over the past week. Employees typically log in during business hours (8 AM - 6 PM local time). Identify any accounts with anomalous login patterns that may indicate compromised credentials.`,
            data: [
                { user: 'jsmith', department: 'Finance', avgLoginHour: '08:45', loginCount: 23, afterHoursLogins: 0, countries: ['US'], anomaly: false },
                { user: 'mjohnson', department: 'HR', avgLoginHour: '09:15', loginCount: 21, afterHoursLogins: 1, countries: ['US'], anomaly: false },
                { user: 'agarcia', department: 'IT', avgLoginHour: '07:30', loginCount: 28, afterHoursLogins: 3, countries: ['US'], anomaly: false },
                { user: 'bwilson', department: 'Marketing', avgLoginHour: '09:00', loginCount: 19, afterHoursLogins: 0, countries: ['US'], anomaly: false },
                { user: 'clee', department: 'Development', avgLoginHour: '10:00', loginCount: 25, afterHoursLogins: 2, countries: ['US'], anomaly: false },
                { user: 'dkim', department: 'Sales', avgLoginHour: '03:22', loginCount: 45, afterHoursLogins: 38, countries: ['US', 'CN', 'RU'], anomaly: true },
                { user: 'etaylor', department: 'Finance', avgLoginHour: '08:30', loginCount: 22, afterHoursLogins: 0, countries: ['US'], anomaly: false },
                { user: 'fmartinez', department: 'Legal', avgLoginHour: '09:45', loginCount: 18, afterHoursLogins: 1, countries: ['US'], anomaly: false },
                { user: 'gbrown', department: 'IT', avgLoginHour: '08:00', loginCount: 30, afterHoursLogins: 5, countries: ['US'], anomaly: false },
                { user: 'hpatel', department: 'Development', avgLoginHour: '09:30', loginCount: 24, afterHoursLogins: 1, countries: ['US'], anomaly: false }
            ],
            clusterSummary: {
                'Business Hours (8-10 AM), Single Country': 9,
                'Off-Hours (3 AM), Multiple Countries': 1
            },
            hints: [
                'Most employees log in between 7:30 AM and 10:00 AM',
                'After-hours logins from multiple countries are highly suspicious',
                'Login counts significantly above average warrant investigation'
            ],
            explanation: 'User dkim has an average login time of 3:22 AM (vs 7:30-10 AM for others), 38 after-hours logins (vs 0-5 normal), logins from 3 countries including China and Russia (vs US only), and 45 total logins (vs 18-30 normal). This strongly indicates compromised credentials being used by foreign actors.'
        },
        {
            id: 'process-execution',
            title: 'Process Execution Clustering',
            briefing: `Endpoint Detection and Response (EDR) captured process execution data. Analyze which processes are running across endpoints to identify outliers that may indicate malware or unauthorized tools.`,
            data: [
                { host: 'WKS-FIN-001', process: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome', parent: 'explorer.exe', executions: 45, anomaly: false },
                { host: 'WKS-FIN-002', process: 'outlook.exe', path: 'C:\\Program Files\\Microsoft Office', parent: 'explorer.exe', executions: 38, anomaly: false },
                { host: 'WKS-HR-001', process: 'excel.exe', path: 'C:\\Program Files\\Microsoft Office', parent: 'explorer.exe', executions: 52, anomaly: false },
                { host: 'WKS-IT-001', process: 'powershell.exe', path: 'C:\\Windows\\System32', parent: 'cmd.exe', executions: 120, anomaly: false },
                { host: 'WKS-DEV-001', process: 'code.exe', path: 'C:\\Program Files\\VS Code', parent: 'explorer.exe', executions: 89, anomaly: false },
                { host: 'WKS-MKT-003', process: 'mimikatz.exe', path: 'C:\\Users\\jdoe\\AppData\\Local\\Temp', parent: 'powershell.exe', executions: 3, anomaly: true },
                { host: 'WKS-FIN-003', process: 'teams.exe', path: 'C:\\Program Files\\Microsoft Teams', parent: 'explorer.exe', executions: 67, anomaly: false },
                { host: 'WKS-HR-002', process: 'word.exe', path: 'C:\\Program Files\\Microsoft Office', parent: 'explorer.exe', executions: 41, anomaly: false },
                { host: 'SRV-DC-01', process: 'lsass.exe', path: 'C:\\Windows\\System32', parent: 'wininit.exe', executions: 1, anomaly: false },
                { host: 'WKS-IT-002', process: 'putty.exe', path: 'C:\\Program Files\\PuTTY', parent: 'explorer.exe', executions: 28, anomaly: false },
                { host: 'WKS-DEV-002', process: 'node.exe', path: 'C:\\Program Files\\nodejs', parent: 'cmd.exe', executions: 156, anomaly: false },
                { host: 'WKS-MKT-001', process: 'slack.exe', path: 'C:\\Program Files\\Slack', parent: 'explorer.exe', executions: 34, anomaly: false }
            ],
            clusterSummary: {
                'Standard Applications (Program Files)': 10,
                'System Processes (Windows)': 1,
                'Suspicious Tool (Temp folder)': 1
            },
            hints: [
                'Legitimate software runs from Program Files or Windows directories',
                'Processes running from Temp or AppData folders are suspicious',
                'Known hacking tools should never appear on corporate endpoints'
            ],
            explanation: 'WKS-MKT-003 is running mimikatz.exe (a known credential dumping tool) from the Temp folder (not a legitimate install path), spawned by PowerShell (common attack vector). Mimikatz should never exist on corporate endpoints - this indicates active credential theft attempt.'
        }
    ],

    flaggedItems: new Set(),

    render() {
        this.currentScenario = 0;
        this.score = 0;
        this.results = [];
        this.flaggedItems = new Set();

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">Threat Hunting: Clustering Analysis</h2>
                <div class="simulation-timer">
                    Scenario <span id="scenario-counter">1</span> of ${this.scenarios.length}
                </div>
            </div>
            
            <div class="simulation-instructions" style="background: rgba(255, 107, 53, 0.1); border-color: rgba(255, 107, 53, 0.3);">
                <h4 style="color: var(--orange);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                        <circle cx="11" cy="11" r="8"/>
                        <path d="m21 21-4.35-4.35"/>
                    </svg>
                    Threat Hunting - Find the Outlier
                </h4>
                <p>Analyze data clusters to identify the "cluster of one" - the anomaly that doesn't belong. In each scenario, most entries follow the same pattern, but one or more are malicious outliers.</p>
            </div>
            
            <div class="simulation-content" id="hunting-content">
                ${this.renderScenario(0)}
            </div>
            
            <div class="simulation-actions">
                <button class="btn btn-outline" onclick="exitSimulation()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="19" y1="12" x2="5" y2="12"/>
                        <polyline points="12 19 5 12 12 5"/>
                    </svg>
                    Exit
                </button>
                <div class="score-display-inline" style="color: var(--orange); font-family: var(--font-display);">
                    Score: <span id="hunting-score">0</span> / ${this.maxScore}
                </div>
            </div>
        `;
    },

    renderScenario(index) {
        const scenario = this.scenarios[index];
        this.flaggedItems = new Set();

        return `
            <div class="hunting-scenario">
                <!-- Briefing -->
                <div style="background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                        <h3 style="color: var(--orange); margin: 0;">Scenario ${index + 1}: ${scenario.title}</h3>
                        <span style="background: rgba(255, 107, 53, 0.2); color: var(--orange); padding: 4px 12px; border-radius: 12px; font-size: 0.8rem;">200 pts</span>
                    </div>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">${scenario.briefing}</p>
                </div>
                
                <!-- Cluster Summary -->
                <div style="display: grid; grid-template-columns: 1fr 300px; gap: 20px; margin-bottom: 20px;">
                    <!-- Main Data Table -->
                    <div style="background: #0a0a0a; border-radius: 12px; border: 1px solid var(--border-color); overflow: hidden;">
                        <div style="background: #1a1a1a; padding: 12px 16px; border-bottom: 1px solid var(--border-color);">
                            <span style="color: var(--text-secondary); font-size: 0.85rem;">📊 Data Points - Click to flag suspicious entries</span>
                        </div>
                        <div style="overflow-x: auto; max-height: 350px; overflow-y: auto;">
                            ${this.renderDataTable(scenario)}
                        </div>
                    </div>
                    
                    <!-- Cluster Summary Panel -->
                    <div>
                        <div style="background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 16px;">
                            <h4 style="color: var(--cyan); margin-bottom: 16px; font-size: 0.9rem;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="vertical-align: middle;">
                                    <circle cx="12" cy="12" r="10"/>
                                    <circle cx="12" cy="12" r="3"/>
                                </svg>
                                Cluster Distribution
                            </h4>
                            ${Object.entries(scenario.clusterSummary).map(([cluster, count]) => `
                                <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border-color);">
                                    <span style="color: ${count === 1 ? 'var(--red)' : 'var(--text-secondary)'}; font-size: 0.85rem;">${cluster}</span>
                                    <span style="font-family: var(--font-display); color: ${count === 1 ? 'var(--red)' : 'var(--cyan)'}; font-weight: 600;">${count}</span>
                                </div>
                            `).join('')}
                        </div>
                        
                        <div style="background: rgba(0, 245, 255, 0.05); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 8px; padding: 12px;">
                            <span style="color: var(--cyan); font-size: 0.85rem; display: block; margin-bottom: 8px;">💡 Hints:</span>
                            <ul style="color: var(--text-muted); font-size: 0.8rem; margin-left: 16px;">
                                ${scenario.hints.map(hint => `<li style="margin-bottom: 4px;">${hint}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- Actions -->
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span id="flagged-count" style="color: var(--text-secondary);">0 items flagged</span>
                    <button class="btn btn-primary" onclick="ThreatHuntingSimulation.submitScenario()" style="background: linear-gradient(135deg, var(--orange), #ff8c00);">
                        Submit Analysis
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <polyline points="9 11 12 14 22 4"/>
                            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;
    },

    renderDataTable(scenario) {
        const columns = Object.keys(scenario.data[0]).filter(k => k !== 'anomaly');

        return `
            <table style="width: 100%; border-collapse: collapse; font-family: 'Monaco', 'Consolas', monospace; font-size: 0.75rem;">
                <thead>
                    <tr style="background: var(--bg-tertiary);">
                        <th style="padding: 10px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color); width: 40px;">Flag</th>
                        ${columns.map(col => `
                            <th style="padding: 10px 12px; text-align: left; color: var(--cyan); border-bottom: 1px solid var(--border-color);">${this.formatColumnName(col)}</th>
                        `).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${scenario.data.map((row, idx) => `
                        <tr data-index="${idx}" style="border-bottom: 1px solid var(--border-color); cursor: pointer; transition: all 0.2s;" onclick="ThreatHuntingSimulation.toggleFlag(${idx})">
                            <td style="padding: 8px 12px;">
                                <button class="hunt-flag-btn" data-flagged="false" style="width: 24px; height: 24px; border-radius: 4px; border: 1px solid var(--border-color); background: transparent; cursor: pointer; display: flex; align-items: center; justify-content: center; color: var(--text-muted);">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                        <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>
                                        <line x1="4" y1="22" x2="4" y2="15"/>
                                    </svg>
                                </button>
                            </td>
                            ${columns.map(col => `
                                <td style="padding: 8px 12px; color: ${this.getCellColor(col, row[col], row)};">${this.formatCellValue(col, row[col])}</td>
                            `).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    },

    formatColumnName(name) {
        return name.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
    },

    formatCellValue(col, value) {
        if (Array.isArray(value)) return value.join(', ');
        if (typeof value === 'number' && value > 1000) return value.toLocaleString();
        return value;
    },

    getCellColor(col, value, row) {
        // Highlight suspicious values
        if (col === 'country' && value !== 'US') return 'var(--yellow)';
        if (col === 'countries' && Array.isArray(value) && value.length > 1) return 'var(--yellow)';
        if (col === 'resolver' && value !== '192.168.1.10') return 'var(--yellow)';
        if (col === 'queryType' && value === 'TXT') return 'var(--yellow)';
        if (col === 'path' && value.includes('Temp')) return 'var(--red)';
        if (col === 'process' && value.toLowerCase().includes('mimikatz')) return 'var(--red)';
        if (col === 'afterHoursLogins' && value > 10) return 'var(--yellow)';
        return 'var(--text-primary)';
    },

    init() {
        // Nothing special needed
    },

    toggleFlag(index) {
        const row = document.querySelector(`tr[data-index="${index}"]`);
        const btn = row.querySelector('.hunt-flag-btn');
        const svg = btn.querySelector('svg');

        if (this.flaggedItems.has(index)) {
            this.flaggedItems.delete(index);
            row.style.background = 'transparent';
            btn.style.background = 'transparent';
            btn.style.borderColor = 'var(--border-color)';
            btn.style.color = 'var(--text-muted)';
            svg.setAttribute('fill', 'none');
        } else {
            this.flaggedItems.add(index);
            row.style.background = 'rgba(255, 107, 53, 0.1)';
            btn.style.background = 'rgba(255, 107, 53, 0.2)';
            btn.style.borderColor = 'var(--orange)';
            btn.style.color = 'var(--orange)';
            svg.setAttribute('fill', 'currentColor');
        }

        document.getElementById('flagged-count').textContent = `${this.flaggedItems.size} items flagged`;
    },

    submitScenario() {
        const scenario = this.scenarios[this.currentScenario];
        const anomalyIndices = new Set(
            scenario.data.map((item, idx) => item.anomaly ? idx : -1).filter(i => i >= 0)
        );

        let correct = true;
        let points = 0;

        // Check if flagged items match anomalies
        const correctFlags = [...this.flaggedItems].filter(i => anomalyIndices.has(i)).length;
        const falsePositives = [...this.flaggedItems].filter(i => !anomalyIndices.has(i)).length;
        const missedAnomalies = [...anomalyIndices].filter(i => !this.flaggedItems.has(i)).length;

        if (correctFlags === anomalyIndices.size && falsePositives === 0) {
            points = 200;
            correct = true;
        } else {
            points = Math.max(0, (correctFlags * 100) - (falsePositives * 50) - (missedAnomalies * 50));
            correct = false;
        }

        this.score += points;
        this.results.push({
            scenarioId: scenario.id,
            correct: correct,
            points: points,
            correctFlags: correctFlags,
            falsePositives: falsePositives,
            missedAnomalies: missedAnomalies
        });

        // Update score display
        document.getElementById('hunting-score').textContent = this.score;

        // Visual feedback
        scenario.data.forEach((item, idx) => {
            const row = document.querySelector(`tr[data-index="${idx}"]`);
            if (item.anomaly && this.flaggedItems.has(idx)) {
                row.style.background = 'rgba(0, 255, 136, 0.15)';
                row.style.borderLeft = '3px solid var(--green)';
            } else if (item.anomaly && !this.flaggedItems.has(idx)) {
                row.style.background = 'rgba(255, 217, 61, 0.15)';
                row.style.borderLeft = '3px solid var(--yellow)';
            } else if (!item.anomaly && this.flaggedItems.has(idx)) {
                row.style.background = 'rgba(255, 56, 96, 0.15)';
                row.style.borderLeft = '3px solid var(--red)';
            }
        });

        // Show explanation
        this.showExplanation(scenario, correct, points);
    },

    showExplanation(scenario, correct, points) {
        const explanationDiv = document.createElement('div');
        explanationDiv.style.cssText = `
            margin-top: 20px; 
            padding: 20px; 
            background: ${correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 217, 61, 0.1)'}; 
            border: 1px solid ${correct ? 'var(--green)' : 'var(--yellow)'}; 
            border-radius: 12px;
        `;
        explanationDiv.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h4 style="color: ${correct ? 'var(--green)' : 'var(--yellow)'}; margin: 0;">
                    ${correct ? '✓ Perfect Analysis!' : '⚠ Partial Credit'} (+${points} pts)
                </h4>
            </div>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px;">
                <strong>Explanation:</strong> ${scenario.explanation}
            </p>
            ${this.currentScenario < this.scenarios.length - 1 ? `
                <button class="btn btn-primary" onclick="ThreatHuntingSimulation.nextScenario()" style="width: 100%;">
                    Next Scenario
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <line x1="5" y1="12" x2="19" y2="12"/>
                        <polyline points="12 5 19 12 12 19"/>
                    </svg>
                </button>
            ` : `
                <button class="btn btn-primary" onclick="ThreatHuntingSimulation.complete()" style="width: 100%;">
                    View Final Results
                </button>
            `}
        `;

        document.querySelector('.hunting-scenario').appendChild(explanationDiv);

        // Disable further flagging
        document.querySelectorAll('tr[data-index]').forEach(row => {
            row.style.pointerEvents = 'none';
        });
    },

    nextScenario() {
        this.currentScenario++;
        document.getElementById('scenario-counter').textContent = this.currentScenario + 1;
        document.getElementById('hunting-content').innerHTML = this.renderScenario(this.currentScenario);
    },

    complete() {
        const feedback = this.results.map((result, idx) => {
            const scenario = this.scenarios[idx];
            return {
                correct: result.correct,
                title: `Scenario ${idx + 1}: ${scenario.title}`,
                explanation: result.correct
                    ? 'You correctly identified all anomalies!'
                    : `Missed ${result.missedAnomalies} anomalies, ${result.falsePositives} false positives`
            };
        });

        completeSimulation('threat-hunting', this.score, this.maxScore, feedback);
    }
};

// Export for global access
window.ThreatHuntingSimulation = ThreatHuntingSimulation;
