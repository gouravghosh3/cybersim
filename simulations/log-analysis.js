/**
 * Log Analysis Simulation
 * Analyze SIEM logs to identify suspicious activity
 */

const LogAnalysisSimulation = {
    logs: [],
    selectedLogs: new Set(),
    maliciousLogs: new Set(),

    scenarios: [
        {
            id: 'brute-force',
            title: 'Brute Force Attack Detection',
            description: 'Analyze authentication logs to identify a brute force attack against the corporate VPN.',
            logs: [
                { id: 1, timestamp: '2024-01-15 08:15:23', level: 'INFO', source: 'vpn-gateway', message: 'User john.smith@corp.com authenticated successfully from 192.168.1.45', malicious: false },
                { id: 2, timestamp: '2024-01-15 08:17:45', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for admin@corp.com from 45.33.32.156', malicious: true },
                { id: 3, timestamp: '2024-01-15 08:17:46', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for admin@corp.com from 45.33.32.156', malicious: true },
                { id: 4, timestamp: '2024-01-15 08:17:47', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for admin@corp.com from 45.33.32.156', malicious: true },
                { id: 5, timestamp: '2024-01-15 08:18:02', level: 'INFO', source: 'mail-server', message: 'Email delivered to sarah.jones@corp.com from newsletter@updates.com', malicious: false },
                { id: 6, timestamp: '2024-01-15 08:17:48', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for admin@corp.com from 45.33.32.156', malicious: true },
                { id: 7, timestamp: '2024-01-15 08:17:49', level: 'CRITICAL', source: 'vpn-gateway', message: 'Account admin@corp.com locked - 5 failed attempts from 45.33.32.156', malicious: true },
                { id: 8, timestamp: '2024-01-15 08:20:15', level: 'INFO', source: 'file-server', message: 'User mike.brown@corp.com accessed /shared/reports/q4-2023.pdf', malicious: false },
                { id: 9, timestamp: '2024-01-15 08:22:33', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for root@corp.com from 45.33.32.156', malicious: true },
                { id: 10, timestamp: '2024-01-15 08:22:34', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for administrator@corp.com from 45.33.32.156', malicious: true },
                { id: 11, timestamp: '2024-01-15 08:25:00', level: 'INFO', source: 'dns-server', message: 'Query for mail.corp.com from 192.168.1.100', malicious: false },
                { id: 12, timestamp: '2024-01-15 08:22:35', level: 'WARNING', source: 'vpn-gateway', message: 'Failed login attempt for sysadmin@corp.com from 45.33.32.156', malicious: true }
            ]
        },
        {
            id: 'privilege-escalation',
            title: 'Privilege Escalation Detection',
            description: 'Review system logs to identify unauthorized privilege escalation attempts.',
            logs: [
                { id: 1, timestamp: '2024-01-15 14:30:12', level: 'INFO', source: 'linux-srv01', message: 'User jdoe logged in via SSH from 192.168.1.50', malicious: false },
                { id: 2, timestamp: '2024-01-15 14:32:45', level: 'WARNING', source: 'linux-srv01', message: 'sudo: jdoe : command not allowed ; COMMAND=/usr/bin/passwd root', malicious: true },
                { id: 3, timestamp: '2024-01-15 14:33:01', level: 'INFO', source: 'web-server', message: 'HTTP 200 GET /api/users from 192.168.1.75', malicious: false },
                { id: 4, timestamp: '2024-01-15 14:35:22', level: 'CRITICAL', source: 'linux-srv01', message: 'sudo: jdoe : command not allowed ; COMMAND=/bin/chmod 777 /etc/shadow', malicious: true },
                { id: 5, timestamp: '2024-01-15 14:36:00', level: 'INFO', source: 'backup-srv', message: 'Daily backup completed successfully', malicious: false },
                { id: 6, timestamp: '2024-01-15 14:38:15', level: 'ERROR', source: 'linux-srv01', message: 'PAM: Authentication failure for root from jdoe session', malicious: true },
                { id: 7, timestamp: '2024-01-15 14:40:00', level: 'INFO', source: 'mail-server', message: 'Outbound email from alerts@corp.com to admin@corp.com', malicious: false },
                { id: 8, timestamp: '2024-01-15 14:42:33', level: 'WARNING', source: 'linux-srv01', message: 'Suspicious file created: /tmp/.hidden/exploit.sh by jdoe', malicious: true },
                { id: 9, timestamp: '2024-01-15 14:45:00', level: 'INFO', source: 'dns-server', message: 'Zone transfer completed for corp.com', malicious: false },
                { id: 10, timestamp: '2024-01-15 14:47:22', level: 'CRITICAL', source: 'linux-srv01', message: 'Kernel: Possible exploit attempt - buffer overflow detected in process 4521', malicious: true }
            ]
        }
    ],

    currentScenario: null,

    render() {
        // Select random scenario
        // Fixed scenario for competition fairness (no randomization)
        this.currentScenario = this.scenarios[0];
        this.logs = [...this.currentScenario.logs].sort((a, b) => a.id - b.id);
        this.maliciousLogs = new Set(this.logs.filter(l => l.malicious).map(l => l.id));
        this.selectedLogs = new Set();

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">${this.currentScenario.title}</h2>
                <div class="simulation-timer">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <polyline points="12 6 12 12 16 14"/>
                    </svg>
                    <span id="sim-timer">00:00</span>
                </div>
            </div>
            
            <div class="simulation-instructions">
                <h4>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="16" x2="12" y2="12"/>
                        <line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                    Mission Briefing
                </h4>
                <p>${this.currentScenario.description} Click on all log entries that indicate malicious activity, then submit your analysis.</p>
            </div>
            
            <div class="simulation-content">
                <div class="log-viewer" id="log-viewer">
                    ${this.logs.map(log => `
                        <div class="log-entry" data-id="${log.id}" onclick="LogAnalysisSimulation.toggleLog(${log.id})">
                            <div class="log-checkbox"></div>
                            <span class="log-timestamp">${log.timestamp}</span>
                            <span class="log-level ${log.level.toLowerCase()}">${log.level}</span>
                            <span class="log-source">[${log.source}]</span>
                            <span class="log-message">${log.message}</span>
                        </div>
                    `).join('')}
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
                    <span id="selected-count" style="margin-right: 16px; color: var(--text-secondary);">0 logs selected</span>
                    <button class="btn btn-primary" onclick="LogAnalysisSimulation.submit()">
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
        this.startTimer();
    },

    startTimer() {
        this.startTime = Date.now();
        this.timerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
            const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
            const secs = (elapsed % 60).toString().padStart(2, '0');
            document.getElementById('sim-timer').textContent = `${mins}:${secs}`;
        }, 1000);
    },

    toggleLog(id) {
        const entry = document.querySelector(`.log-entry[data-id="${id}"]`);

        if (this.selectedLogs.has(id)) {
            this.selectedLogs.delete(id);
            entry.classList.remove('selected');
        } else {
            this.selectedLogs.add(id);
            entry.classList.add('selected');
        }

        document.getElementById('selected-count').textContent = `${this.selectedLogs.size} logs selected`;
    },

    submit() {
        clearInterval(this.timerInterval);

        // Calculate score
        let correctHits = 0;
        let falsePositives = 0;
        let missedThreats = 0;
        const feedback = [];

        // Check selected logs
        this.selectedLogs.forEach(id => {
            const log = this.logs.find(l => l.id === id);
            if (this.maliciousLogs.has(id)) {
                correctHits++;
                feedback.push({
                    correct: true,
                    title: `✓ Correctly identified: ${log.source}`,
                    explanation: `Good catch! This log shows ${this.getExplanation(log)}`
                });
            } else {
                falsePositives++;
                feedback.push({
                    correct: false,
                    title: `✗ False positive: ${log.source}`,
                    explanation: `This is normal activity: ${log.message}`
                });
            }
        });

        // Check missed threats
        this.maliciousLogs.forEach(id => {
            if (!this.selectedLogs.has(id)) {
                missedThreats++;
                const log = this.logs.find(l => l.id === id);
                feedback.push({
                    correct: false,
                    title: `⚠ Missed threat: ${log.source}`,
                    explanation: `This log indicates ${this.getExplanation(log)}`
                });
            }
        });

        // Calculate score (100 per correct, -50 per false positive, -25 per miss)
        const maxScore = 500;
        const baseScore = (correctHits / this.maliciousLogs.size) * maxScore;
        const penalties = (falsePositives * 50) + (missedThreats * 25);
        const finalScore = Math.max(0, Math.round(baseScore - penalties));

        // Show results with visual feedback
        this.logs.forEach(log => {
            const entry = document.querySelector(`.log-entry[data-id="${log.id}"]`);
            if (log.malicious && this.selectedLogs.has(log.id)) {
                entry.classList.add('correct');
            } else if (log.malicious && !this.selectedLogs.has(log.id)) {
                entry.classList.add('incorrect');
                entry.style.borderColor = 'var(--yellow)';
            } else if (!log.malicious && this.selectedLogs.has(log.id)) {
                entry.classList.add('incorrect');
            }
        });

        setTimeout(() => {
            completeSimulation('log-analysis', finalScore, maxScore, feedback);
        }, 1500);
    },

    getExplanation(log) {
        if (log.message.includes('Failed login')) return 'repeated failed authentication attempts, indicating a brute force attack';
        if (log.message.includes('locked')) return 'an account lockout due to multiple failed attempts';
        if (log.message.includes('sudo') && log.message.includes('not allowed')) return 'unauthorized privilege escalation attempt';
        if (log.message.includes('PAM')) return 'a direct attempt to gain root access';
        if (log.message.includes('exploit') || log.message.includes('overflow')) return 'potential exploit or buffer overflow attack';
        if (log.message.includes('.hidden') || log.message.includes('Suspicious')) return 'creation of suspicious hidden files';
        return 'suspicious activity that warrants investigation';
    }
};

// Export for global access
window.LogAnalysisSimulation = LogAnalysisSimulation;
