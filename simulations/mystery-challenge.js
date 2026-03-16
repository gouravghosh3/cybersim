/**
 * Mystery Bonus Challenge - SOC Alert Triage
 * Unlocks at 40-minute mark (20 min remaining)
 * 10 alerts, 15 seconds each, classify as TP/FP/Escalate
 * Max Score: 400 (double points)
 */

const MysteryChallenge = {
    alerts: [
        {
            id: 1,
            severity: 'CRITICAL',
            title: 'Ransomware Encryption Detected',
            source: 'EDR - CrowdStrike',
            description: 'Process "svchost_update.exe" is performing rapid file encryption across multiple directories on WORKSTATION-PC42. 1,247 files modified in 30 seconds.',
            indicators: ['Unknown binary hash', 'Mass file modification', 'Entropy increase in files'],
            answer: 'tp',
            explanation: 'Rapid file encryption by an unknown binary is a classic ransomware indicator. The masquerading filename (mimicking svchost) is a red flag.'
        },
        {
            id: 2,
            severity: 'HIGH',
            title: 'Outbound Connection to Known C2 Server',
            source: 'Firewall - Palo Alto',
            description: 'Host 10.50.12.88 initiated HTTPS connection to 185.220.101.34:443 (TOR exit node). Connection lasted 45 minutes with 2.3MB data transferred.',
            indicators: ['Known TOR exit node', 'Extended connection duration', 'Significant data transfer'],
            answer: 'tp',
            explanation: 'Connection to a known TOR exit node with sustained data transfer strongly suggests data exfiltration or C2 communication.'
        },
        {
            id: 3,
            severity: 'MEDIUM',
            title: 'Multiple Failed Login Attempts',
            source: 'SIEM - Splunk',
            description: 'User "john.smith" failed 5 login attempts in 2 minutes from office IP 10.10.5.22, then successfully logged in on attempt 6.',
            indicators: ['5 failed attempts', 'Known office IP', 'Successful login after failures'],
            answer: 'fp',
            explanation: 'This is a typical "forgot password" scenario. The source is a known office IP, the user eventually succeeded, and the attempt count is low. Normal human behavior.'
        },
        {
            id: 4,
            severity: 'HIGH',
            title: 'DNS Tunneling Suspected',
            source: 'DNS Security - Infoblox',
            description: 'Host 10.50.8.115 made 4,500 DNS queries in 10 minutes to subdomain patterns like "a3f8b2c1.data.evil-domain.com". Average query length: 180 characters.',
            indicators: ['Abnormal query volume', 'Long subdomain strings', 'Base64-like patterns'],
            answer: 'tp',
            explanation: 'High-frequency DNS queries with long, encoded-looking subdomains to a single domain is a textbook DNS tunneling pattern used for data exfiltration.'
        },
        {
            id: 5,
            severity: 'LOW',
            title: 'Windows Defender Definition Update',
            source: 'EDR - Microsoft Defender',
            description: 'Automatic update of virus definitions on 342 endpoints. Update source: windowsupdate.microsoft.com. All signatures verified.',
            indicators: ['Mass endpoint activity', 'External download', 'System-initiated'],
            answer: 'fp',
            explanation: 'This is a routine Windows Defender update from the legitimate Microsoft update server. The mass activity is expected during enterprise patch deployment.'
        },
        {
            id: 6,
            severity: 'CRITICAL',
            title: 'Lateral Movement via PsExec',
            source: 'EDR - Carbon Black',
            description: 'Service account "svc_backup" executed PsExec to remotely launch PowerShell on 8 servers in the finance subnet within 3 minutes.',
            indicators: ['PsExec usage', 'Service account pivot', 'Cross-subnet movement', 'Rapid propagation'],
            answer: 'escalate',
            explanation: 'While service accounts can legitimately use remote tools, the rapid cross-subnet PsExec activity targeting specifically the finance subnet is highly suspicious and needs immediate investigation by a senior analyst.'
        },
        {
            id: 7,
            severity: 'MEDIUM',
            title: 'Unusual VPN Connection',
            source: 'VPN Gateway - Cisco AnyConnect',
            description: 'User "sarah.jones" connected via VPN from an IP geolocated to Singapore at 02:30 UTC. Her previous session was from New York 6 hours ago.',
            indicators: ['Impossible travel', 'Off-hours access', 'Geographic anomaly'],
            answer: 'escalate',
            explanation: 'Impossible travel (New York to Singapore in 6 hours with VPN sessions) could indicate credential compromise. However, the user might be genuinely traveling. This needs verification with the user before confirming as malicious.'
        },
        {
            id: 8,
            severity: 'HIGH',
            title: 'Cryptocurrency Mining Detected',
            source: 'Network IDS - Suricata',
            description: 'Host 10.50.15.200 communicating with mining pool stratum+tcp://pool.minexmr.com:4444. CPU usage spiked to 95% on this development server.',
            indicators: ['Mining pool connection', 'Stratum protocol', 'CPU spike'],
            answer: 'tp',
            explanation: 'Direct connection to a known cryptocurrency mining pool using the Stratum protocol is definitive cryptojacking. This server has been compromised.'
        },
        {
            id: 9,
            severity: 'LOW',
            title: 'Scheduled Task Created',
            source: 'Windows Event Log',
            description: 'SYSTEM account created scheduled task "GoogleUpdateCheck" running "C:\\ProgramData\\Google\\update.bat" daily at 03:00. Hash matches no known Google binaries.',
            indicators: ['Persistence mechanism', 'Masquerading name', 'Unknown hash', 'ProgramData location'],
            answer: 'tp',
            explanation: 'Despite the LOW severity rating from the SIEM, this is a true positive. The unknown hash, masquerading filename, and ProgramData location are classic persistence technique indicators (MITRE T1053).'
        },
        {
            id: 10,
            severity: 'MEDIUM',
            title: 'Large Data Upload to Cloud Storage',
            source: 'DLP - Symantec',
            description: 'User "mike.chen" uploaded 850MB to personal Google Drive from his corporate laptop between 17:00-17:30. Mike is in the engineering department.',
            indicators: ['Large upload volume', 'Personal cloud storage', 'End of business day'],
            answer: 'escalate',
            explanation: 'Large data transfers to personal cloud storage could be data theft or could be innocent (e.g., backing up non-sensitive work). DLP policy violation requires investigation but isn\'t definitively malicious without content inspection.'
        }
    ],

    currentAlertIndex: 0,
    answers: [],
    alertTimer: null,
    alertTimeLeft: 15,
    totalTimeLeft: 150, // 10 alerts × 15 seconds
    isActive: false,

    render() {
        this.currentAlertIndex = 0;
        this.answers = [];
        this.alertTimeLeft = 15;
        this.isActive = true;

        return `
            <div class="mystery-sim">
                <div class="mystery-header">
                    <div class="mystery-alert-banner">
                        <span class="alert-pulse"></span>
                        🚨 EMERGENCY ALERT TRIAGE
                    </div>
                    <div class="mystery-meta">
                        <span class="mystery-progress-text">Alert <span id="mystery-current">1</span> of ${this.alerts.length}</span>
                        <span class="mystery-timer" id="mystery-timer">15s</span>
                    </div>
                </div>
                
                <div class="mystery-timer-bar">
                    <div class="mystery-timer-fill" id="mystery-timer-fill"></div>
                </div>

                <div id="mystery-alert-container">
                    <!-- Populated by init -->
                </div>

                <div class="mystery-actions" id="mystery-actions">
                    <button class="mystery-btn tp" onclick="MysteryChallenge.classify('tp')">
                        <span class="mystery-btn-icon">🎯</span>
                        True Positive
                        <span class="mystery-btn-hint">Real threat — take action</span>
                    </button>
                    <button class="mystery-btn fp" onclick="MysteryChallenge.classify('fp')">
                        <span class="mystery-btn-icon">✅</span>
                        False Positive
                        <span class="mystery-btn-hint">Benign — close alert</span>
                    </button>
                    <button class="mystery-btn escalate" onclick="MysteryChallenge.classify('escalate')">
                        <span class="mystery-btn-icon">⬆️</span>
                        Needs Escalation
                        <span class="mystery-btn-hint">Unclear — escalate to senior</span>
                    </button>
                </div>

                <div class="mystery-results" id="mystery-results" style="display:none;">
                    <!-- Shown after all alerts -->
                </div>
            </div>
        `;
    },

    init() {
        this.showAlert(0);
        this.startAlertTimer();
    },

    showAlert(index) {
        if (index >= this.alerts.length) {
            this.finishChallenge();
            return;
        }

        this.currentAlertIndex = index;
        this.alertTimeLeft = 15;
        const alert = this.alerts[index];

        document.getElementById('mystery-current').textContent = index + 1;

        const container = document.getElementById('mystery-alert-container');
        const severityColors = {
            'CRITICAL': '#ff3860',
            'HIGH': '#ff6b35',
            'MEDIUM': '#ffd93d',
            'LOW': '#00ff88'
        };

        container.innerHTML = `
            <div class="alert-card" style="animation: alertSlideIn 0.3s ease">
                <div class="alert-card-header">
                    <span class="alert-severity" style="background: ${severityColors[alert.severity]}20; color: ${severityColors[alert.severity]}; border: 1px solid ${severityColors[alert.severity]}40;">
                        ${alert.severity}
                    </span>
                    <span class="alert-source">${alert.source}</span>
                </div>
                <h3 class="alert-title">${alert.title}</h3>
                <p class="alert-description">${alert.description}</p>
                <div class="alert-indicators">
                    <span class="alert-indicators-label">Indicators:</span>
                    ${alert.indicators.map(i => `<span class="alert-indicator-tag">${i}</span>`).join('')}
                </div>
            </div>
        `;

        // Reset timer bar
        const fill = document.getElementById('mystery-timer-fill');
        fill.style.transition = 'none';
        fill.style.width = '100%';
        requestAnimationFrame(() => {
            fill.style.transition = 'width 15s linear';
            fill.style.width = '0%';
        });
    },

    startAlertTimer() {
        this.alertTimer = setInterval(() => {
            this.alertTimeLeft--;
            const timerEl = document.getElementById('mystery-timer');
            if (timerEl) timerEl.textContent = `${this.alertTimeLeft}s`;

            if (this.alertTimeLeft <= 0) {
                // Auto-skip (counts as wrong)
                this.classify('skip');
            }
        }, 1000);
    },

    classify(classification) {
        if (!this.isActive) return;

        const alert = this.alerts[this.currentAlertIndex];
        this.answers.push({
            alertId: alert.id,
            playerAnswer: classification,
            correctAnswer: alert.answer,
            isCorrect: classification === alert.answer,
            title: alert.title
        });

        this.showAlert(this.currentAlertIndex + 1);
    },

    finishChallenge() {
        this.isActive = false;
        clearInterval(this.alertTimer);

        const correct = this.answers.filter(a => a.isCorrect).length;
        const total = this.alerts.length;
        const score = Math.round((correct / total) * 400);
        const accuracy = Math.round((correct / total) * 100);

        // Build feedback
        const feedback = this.answers.map(a => {
            const alert = this.alerts.find(al => al.id === a.alertId);
            const icon = a.isCorrect ? '✅' : (a.playerAnswer === 'skip' ? '⏭️' : '❌');
            const labels = { tp: 'True Positive', fp: 'False Positive', escalate: 'Escalate', skip: 'Skipped' };
            return `${icon} <strong>${a.title}</strong>: You said ${labels[a.playerAnswer] || 'Skipped'}, correct was ${labels[a.correctAnswer]}. ${alert.explanation}`;
        });

        // Hide actions, show results
        document.getElementById('mystery-actions').style.display = 'none';
        document.getElementById('mystery-alert-container').innerHTML = '';

        const resultsEl = document.getElementById('mystery-results');
        resultsEl.style.display = 'block';
        resultsEl.innerHTML = `
            <div class="mystery-score-display">
                <div class="mystery-score-value">${score}</div>
                <div class="mystery-score-label">BONUS POINTS</div>
                <div class="mystery-accuracy">${correct}/${total} correct (${accuracy}%)</div>
            </div>
            <div class="mystery-feedback">
                <h4>Alert Debrief:</h4>
                ${feedback.map(f => `<div class="mystery-feedback-item">${f}</div>`).join('')}
            </div>
            <button class="btn btn-primary" onclick="completeSimulation('mystery-challenge', ${score}, 400, [])" style="margin-top:20px;">
                Submit Results
            </button>
        `;

        document.querySelector('.mystery-timer-bar').style.display = 'none';
    }
};

window.MysteryChallenge = MysteryChallenge;
