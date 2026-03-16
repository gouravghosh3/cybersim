/**
 * Threat Hunting Simulation - Stacking (Counting)
 * Sort data by frequency to identify outliers - the least common items often hide attackers
 */

const ThreatStackingSimulation = {
    currentScenario: 0,
    score: 0,
    maxScore: 800,
    results: [],

    scenarios: [
        {
            id: 'user-agent-stacking',
            title: 'User Agent Analysis',
            briefing: `Stack User-Agent strings from web server logs. Common browsers appear thousands of times, but attackers often use custom tools with unique User-Agents. Sort by count to find the outliers at the bottom.`,
            data: [
                { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0', category: 'Chrome Windows', count: 45823, anomaly: false },
                { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0.0.0', category: 'Chrome Mac', count: 28456, anomaly: false },
                { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0', category: 'Firefox Windows', count: 12340, anomaly: false },
                { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1', category: 'Safari iOS', count: 18920, anomaly: false },
                { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0', category: 'Edge Windows', count: 8945, anomaly: false },
                { userAgent: 'Mozilla/5.0 (Linux; Android 14) Chrome/120.0.0.0 Mobile', category: 'Chrome Android', count: 15670, anomaly: false },
                { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/17.0', category: 'Safari Mac', count: 9234, anomaly: false },
                { userAgent: 'python-requests/2.28.0', category: 'Python Requests', count: 347, anomaly: false },
                { userAgent: 'curl/7.84.0', category: 'cURL', count: 156, anomaly: false },
                { userAgent: 'Googlebot/2.1 (+http://www.google.com/bot.html)', category: 'Google Bot', count: 2890, anomaly: false },
                { userAgent: 'Mozilla/5.0 (compatible; Cobalt Strike)', category: 'Cobalt Strike', count: 3, anomaly: true },
                { userAgent: 'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)', category: 'Bing Bot', count: 1456, anomaly: false },
                { userAgent: 'Go-http-client/1.1', category: 'Go HTTP', count: 89, anomaly: false },
                { userAgent: 'masscan/1.0 (https://github.com/robertdavidgraham/masscan)', category: 'Masscan', count: 2, anomaly: true }
            ],
            sortField: 'count',
            sortAsc: true,
            hints: [
                'Legitimate traffic generates high counts; low counts are suspicious',
                'Look for hacking tool signatures (Cobalt Strike, Masscan, Metasploit)',
                'Items with count < 10 warrant investigation'
            ],
            explanation: 'Cobalt Strike (3 hits) and Masscan (2 hits) are penetration testing/attack tools that should never appear in production traffic. Their extremely low count compared to legitimate browsers (thousands of hits) makes them stand out when data is stacked by frequency.'
        },
        {
            id: 'parent-process-stacking',
            title: 'Parent Process Analysis',
            briefing: `Stack processes by their parent process. Most applications are spawned by legitimate parents like explorer.exe or services.exe. Unusual parent-child relationships often indicate malware.`,
            data: [
                { childProcess: 'chrome.exe', parentProcess: 'explorer.exe', count: 4521, anomaly: false },
                { childProcess: 'outlook.exe', parentProcess: 'explorer.exe', count: 2890, anomaly: false },
                { childProcess: 'teams.exe', parentProcess: 'explorer.exe', count: 2456, anomaly: false },
                { childProcess: 'code.exe', parentProcess: 'explorer.exe', count: 1823, anomaly: false },
                { childProcess: 'svchost.exe', parentProcess: 'services.exe', count: 15670, anomaly: false },
                { childProcess: 'powershell.exe', parentProcess: 'explorer.exe', count: 890, anomaly: false },
                { childProcess: 'cmd.exe', parentProcess: 'explorer.exe', count: 567, anomaly: false },
                { childProcess: 'notepad.exe', parentProcess: 'explorer.exe', count: 1234, anomaly: false },
                { childProcess: 'powershell.exe', parentProcess: 'excel.exe', count: 12, anomaly: true },
                { childProcess: 'cmd.exe', parentProcess: 'winword.exe', count: 8, anomaly: true },
                { childProcess: 'mshta.exe', parentProcess: 'outlook.exe', count: 3, anomaly: true },
                { childProcess: 'wscript.exe', parentProcess: 'services.exe', count: 89, anomaly: false },
                { childProcess: 'SearchIndexer.exe', parentProcess: 'services.exe', count: 2341, anomaly: false },
                { childProcess: 'RuntimeBroker.exe', parentProcess: 'svchost.exe', count: 4567, anomaly: false }
            ],
            sortField: 'count',
            sortAsc: true,
            hints: [
                'Office apps (Word, Excel) should not spawn command interpreters',
                'PowerShell/cmd from Office = likely macro malware',
                'mshta.exe (HTML Application Host) is commonly abused by attackers'
            ],
            explanation: 'PowerShell from Excel (12), cmd from Word (8), and mshta from Outlook (3) are classic malicious macro/attachment behaviors. Legitimate office workflows rarely spawn command interpreters - these low-count parent-child pairs indicate active compromise.'
        },
        {
            id: 'outbound-port-stacking',
            title: 'Outbound Port Analysis',
            briefing: `Stack outbound connections by destination port. Most corporate traffic uses standard ports (80, 443, 53). Unusual ports with low traffic volumes may indicate C2 communication or data exfiltration.`,
            data: [
                { port: 443, protocol: 'HTTPS', description: 'Secure Web Traffic', count: 892456, anomaly: false },
                { port: 80, protocol: 'HTTP', description: 'Web Traffic', count: 234567, anomaly: false },
                { port: 53, protocol: 'DNS', description: 'DNS Queries', count: 156789, anomaly: false },
                { port: 993, protocol: 'IMAPS', description: 'Secure Email', count: 45678, anomaly: false },
                { port: 587, protocol: 'SMTP', description: 'Email Submission', count: 23456, anomaly: false },
                { port: 22, protocol: 'SSH', description: 'Secure Shell', count: 8934, anomaly: false },
                { port: 3389, protocol: 'RDP', description: 'Remote Desktop', count: 5678, anomaly: false },
                { port: 123, protocol: 'NTP', description: 'Time Sync', count: 12345, anomaly: false },
                { port: 8080, protocol: 'HTTP-Alt', description: 'Alt Web Traffic', count: 3456, anomaly: false },
                { port: 4444, protocol: 'TCP', description: 'Unknown', count: 23, anomaly: true },
                { port: 6667, protocol: 'IRC', description: 'IRC (Bot C2)', count: 8, anomaly: true },
                { port: 31337, protocol: 'TCP', description: 'Unknown', count: 4, anomaly: true },
                { port: 445, protocol: 'SMB', description: 'File Sharing', count: 67890, anomaly: false },
                { port: 389, protocol: 'LDAP', description: 'Directory', count: 34567, anomaly: false }
            ],
            sortField: 'count',
            sortAsc: true,
            hints: [
                'Port 4444 is Metasploit default listener port',
                'Port 6667 (IRC) is classic botnet C2',
                'Port 31337 ("eleet") is hacker culture port'
            ],
            explanation: 'Ports 4444 (Metasploit default - 23 connections), 6667 (IRC botnet C2 - 8 connections), and 31337 (classic hacker port - 4 connections) are extremely suspicious at any count. Their low frequency among millions of normal connections makes stacking essential to find them.'
        },
        {
            id: 'file-extension-stacking',
            title: 'Downloaded File Extension Analysis',
            briefing: `Stack downloaded files by extension. Common extensions like .pdf, .docx, .png appear frequently. Rare extensions, especially executable types, may indicate malware delivery.`,
            data: [
                { extension: '.pdf', category: 'Documents', description: 'PDF Documents', count: 45678, anomaly: false },
                { extension: '.docx', category: 'Documents', description: 'Word Documents', count: 34567, anomaly: false },
                { extension: '.xlsx', category: 'Documents', description: 'Excel Spreadsheets', count: 28901, anomaly: false },
                { extension: '.png', category: 'Images', description: 'PNG Images', count: 123456, anomaly: false },
                { extension: '.jpg', category: 'Images', description: 'JPEG Images', count: 98765, anomaly: false },
                { extension: '.zip', category: 'Archives', description: 'ZIP Archives', count: 12345, anomaly: false },
                { extension: '.pptx', category: 'Documents', description: 'PowerPoint', count: 8901, anomaly: false },
                { extension: '.gif', category: 'Images', description: 'GIF Images', count: 34567, anomaly: false },
                { extension: '.svg', category: 'Images', description: 'SVG Graphics', count: 11234, anomaly: false },
                { extension: '.hta', category: 'Executable', description: 'HTML Application', count: 7, anomaly: true },
                { extension: '.scr', category: 'Executable', description: 'Screensaver (EXE)', count: 3, anomaly: true },
                { extension: '.js', category: 'Scripts', description: 'JavaScript File', count: 4560, anomaly: false },
                { extension: '.ps1', category: 'Scripts', description: 'PowerShell Script', count: 156, anomaly: false },
                { extension: '.iso', category: 'Disk Image', description: 'ISO Disk Image', count: 12, anomaly: true },
                { extension: '.lnk', category: 'Shortcut', description: 'Windows Shortcut', count: 5, anomaly: true }
            ],
            sortField: 'count',
            sortAsc: true,
            hints: [
                '.hta files execute code and bypass some security controls',
                '.scr files are executables disguised as screensavers',
                '.iso files bypass Mark-of-the-Web protections',
                '.lnk files can execute arbitrary commands'
            ],
            explanation: '.hta (7), .scr (3), .iso (12), and .lnk (5) are file types commonly used in malware delivery because they can execute code or bypass security controls. Their extremely low download count compared to normal files (thousands) makes them easy to spot when stacked by frequency.'
        }
    ],

    flaggedItems: new Set(),
    sortedData: [],

    render() {
        this.currentScenario = 0;
        this.score = 0;
        this.results = [];
        this.flaggedItems = new Set();

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">Threat Hunting: Stacking Analysis</h2>
                <div class="simulation-timer">
                    Scenario <span id="stack-scenario-counter">1</span> of ${this.scenarios.length}
                </div>
            </div>
            
            <div class="simulation-instructions" style="background: rgba(255, 56, 96, 0.1); border-color: rgba(255, 56, 96, 0.3);">
                <h4 style="color: var(--red);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                        <line x1="12" y1="20" x2="12" y2="10"/>
                        <line x1="18" y1="20" x2="18" y2="4"/>
                        <line x1="6" y1="20" x2="6" y2="16"/>
                    </svg>
                    Threat Hunting - Find the Least Common
                </h4>
                <p>Sort data by frequency and look at the bottom - the least common items are often where attackers hide. Common items are "noise," rare items are signals.</p>
            </div>
            
            <div class="simulation-content" id="stacking-content">
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
                <div class="score-display-inline" style="color: var(--red); font-family: var(--font-display);">
                    Score: <span id="stacking-score">0</span> / ${this.maxScore}
                </div>
            </div>
        `;
    },

    renderScenario(index) {
        const scenario = this.scenarios[index];
        this.flaggedItems = new Set();

        // Sort data by count ascending (least frequent first)
        this.sortedData = [...scenario.data].sort((a, b) => a.count - b.count);

        return `
            <div class="stacking-scenario">
                <!-- Briefing -->
                <div style="background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                        <h3 style="color: var(--red); margin: 0;">Scenario ${index + 1}: ${scenario.title}</h3>
                        <span style="background: rgba(255, 56, 96, 0.2); color: var(--red); padding: 4px 12px; border-radius: 12px; font-size: 0.8rem;">200 pts</span>
                    </div>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">${scenario.briefing}</p>
                    
                    <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                        ${scenario.hints.map(hint => `
                            <span style="background: rgba(0, 245, 255, 0.1); color: var(--cyan); padding: 6px 12px; border-radius: 16px; font-size: 0.8rem;">💡 ${hint}</span>
                        `).join('')}
                    </div>
                </div>
                
                <!-- Frequency Bar Chart -->
                <div style="background: #0a0a0a; border-radius: 12px; border: 1px solid var(--border-color); overflow: hidden; margin-bottom: 20px;">
                    <div style="background: #1a1a1a; padding: 12px 16px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: var(--text-secondary); font-size: 0.85rem;">📊 Stacked by Frequency (Lowest First) - Flag suspicious items</span>
                        <span style="color: var(--text-muted); font-size: 0.8rem;">↑ Most common at bottom, outliers at top</span>
                    </div>
                    <div style="padding: 20px; max-height: 400px; overflow-y: auto;">
                        ${this.sortedData.map((item, idx) => {
            const maxCount = Math.max(...scenario.data.map(d => d.count));
            const barWidth = Math.max(2, (item.count / maxCount) * 100);
            const isLowCount = item.count < (maxCount * 0.001); // Less than 0.1% of max

            return `
                                <div data-index="${idx}" class="stack-row" onclick="ThreatStackingSimulation.toggleFlag(${idx})" style="display: flex; align-items: center; padding: 10px; margin-bottom: 8px; border-radius: 8px; cursor: pointer; transition: all 0.2s; border: 1px solid transparent; ${isLowCount ? 'background: rgba(255, 56, 96, 0.05);' : ''}">
                                    <button class="stack-flag-btn" data-flagged="false" style="width: 28px; height: 28px; min-width: 28px; border-radius: 4px; border: 1px solid var(--border-color); background: transparent; cursor: pointer; display: flex; align-items: center; justify-content: center; color: var(--text-muted); margin-right: 12px;">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                            <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>
                                            <line x1="4" y1="22" x2="4" y2="15"/>
                                        </svg>
                                    </button>
                                    <div style="flex: 1; min-width: 0;">
                                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                            <span style="color: ${isLowCount ? 'var(--red)' : 'var(--text-primary)'}; font-size: 0.85rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 60%;" title="${this.getPrimaryField(item)}">${this.getPrimaryField(item)}</span>
                                            <span style="color: ${isLowCount ? 'var(--red)' : 'var(--cyan)'}; font-family: var(--font-display); font-weight: 600; font-size: 0.9rem;">${item.count.toLocaleString()}</span>
                                        </div>
                                        <div style="height: 8px; background: var(--bg-tertiary); border-radius: 4px; overflow: hidden;">
                                            <div style="height: 100%; width: ${barWidth}%; background: ${isLowCount ? 'linear-gradient(90deg, var(--red), #ff6b6b)' : 'linear-gradient(90deg, var(--cyan), var(--purple))'}; border-radius: 4px; transition: width 0.3s;"></div>
                                        </div>
                                        <div style="margin-top: 4px; color: var(--text-muted); font-size: 0.75rem;">${this.getSecondaryField(item)}</div>
                                    </div>
                                </div>
                            `;
        }).join('')}
                    </div>
                </div>
                
                <!-- Actions -->
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span id="stack-flagged-count" style="color: var(--text-secondary);">0 items flagged</span>
                    <button class="btn btn-primary" onclick="ThreatStackingSimulation.submitScenario()" style="background: linear-gradient(135deg, var(--red), #ff6b6b);">
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

    getPrimaryField(item) {
        if (item.userAgent) return item.category || item.userAgent.substring(0, 50);
        if (item.childProcess) return `${item.childProcess} ← ${item.parentProcess}`;
        if (item.port) return `Port ${item.port} (${item.protocol})`;
        if (item.extension) return `${item.extension} - ${item.description}`;
        return Object.values(item)[0];
    },

    getSecondaryField(item) {
        if (item.userAgent) return item.userAgent.substring(0, 80) + (item.userAgent.length > 80 ? '...' : '');
        if (item.childProcess) return 'Parent-Child relationship';
        if (item.port) return item.description;
        if (item.extension) return item.category;
        return '';
    },

    init() {
        // Nothing special needed
    },

    toggleFlag(index) {
        const row = document.querySelector(`.stack-row[data-index="${index}"]`);
        const btn = row.querySelector('.stack-flag-btn');
        const svg = btn.querySelector('svg');

        if (this.flaggedItems.has(index)) {
            this.flaggedItems.delete(index);
            row.style.borderColor = 'transparent';
            row.style.background = this.sortedData[index].count < (Math.max(...this.sortedData.map(d => d.count)) * 0.001) ? 'rgba(255, 56, 96, 0.05)' : 'transparent';
            btn.style.background = 'transparent';
            btn.style.borderColor = 'var(--border-color)';
            btn.style.color = 'var(--text-muted)';
            svg.setAttribute('fill', 'none');
        } else {
            this.flaggedItems.add(index);
            row.style.borderColor = 'var(--red)';
            row.style.background = 'rgba(255, 56, 96, 0.15)';
            btn.style.background = 'rgba(255, 56, 96, 0.2)';
            btn.style.borderColor = 'var(--red)';
            btn.style.color = 'var(--red)';
            svg.setAttribute('fill', 'currentColor');
        }

        document.getElementById('stack-flagged-count').textContent = `${this.flaggedItems.size} items flagged`;
    },

    submitScenario() {
        const scenario = this.scenarios[this.currentScenario];
        const anomalyIndices = new Set(
            this.sortedData.map((item, idx) => item.anomaly ? idx : -1).filter(i => i >= 0)
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
            points = Math.max(0, (correctFlags * 80) - (falsePositives * 40) - (missedAnomalies * 30));
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
        document.getElementById('stacking-score').textContent = this.score;

        // Visual feedback
        this.sortedData.forEach((item, idx) => {
            const row = document.querySelector(`.stack-row[data-index="${idx}"]`);
            if (item.anomaly && this.flaggedItems.has(idx)) {
                row.style.background = 'rgba(0, 255, 136, 0.15)';
                row.style.borderColor = 'var(--green)';
            } else if (item.anomaly && !this.flaggedItems.has(idx)) {
                row.style.background = 'rgba(255, 217, 61, 0.15)';
                row.style.borderColor = 'var(--yellow)';
            } else if (!item.anomaly && this.flaggedItems.has(idx)) {
                row.style.background = 'rgba(255, 56, 96, 0.15)';
                row.style.borderColor = 'var(--red)';
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
                <button class="btn btn-primary" onclick="ThreatStackingSimulation.nextScenario()" style="width: 100%;">
                    Next Scenario
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <line x1="5" y1="12" x2="19" y2="12"/>
                        <polyline points="12 5 19 12 12 19"/>
                    </svg>
                </button>
            ` : `
                <button class="btn btn-primary" onclick="ThreatStackingSimulation.complete()" style="width: 100%;">
                    View Final Results
                </button>
            `}
        `;

        document.querySelector('.stacking-scenario').appendChild(explanationDiv);

        // Disable further flagging
        document.querySelectorAll('.stack-row').forEach(row => {
            row.style.pointerEvents = 'none';
        });
    },

    nextScenario() {
        this.currentScenario++;
        document.getElementById('stack-scenario-counter').textContent = this.currentScenario + 1;
        document.getElementById('stacking-content').innerHTML = this.renderScenario(this.currentScenario);
    },

    complete() {
        const feedback = this.results.map((result, idx) => {
            const scenario = this.scenarios[idx];
            return {
                correct: result.correct,
                title: `Scenario ${idx + 1}: ${scenario.title}`,
                explanation: result.correct
                    ? 'You correctly identified all outliers!'
                    : `Missed ${result.missedAnomalies} anomalies, ${result.falsePositives} false positives`
            };
        });

        completeSimulation('threat-stacking', this.score, this.maxScore, feedback);
    }
};

// Export for global access
window.ThreatStackingSimulation = ThreatStackingSimulation;
