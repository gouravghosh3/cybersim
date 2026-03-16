/**
 * Splunk Query Simulation
 * Write SPL queries to analyze security data
 */

const SplunkQuerySimulation = {
    currentChallenge: 0,
    score: 0,
    maxScore: 600,
    results: [],

    // Simulated Splunk data
    sampleData: [
        { _time: '2024-01-15 09:00:01', host: 'web-srv01', source: 'access.log', action: 'login', user: 'jsmith', status: 'success', src_ip: '192.168.1.100' },
        { _time: '2024-01-15 09:00:15', host: 'web-srv01', source: 'access.log', action: 'login', user: 'admin', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:00:16', host: 'web-srv01', source: 'access.log', action: 'login', user: 'admin', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:00:17', host: 'web-srv01', source: 'access.log', action: 'login', user: 'admin', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:00:18', host: 'web-srv01', source: 'access.log', action: 'login', user: 'admin', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:00:19', host: 'web-srv01', source: 'access.log', action: 'login', user: 'admin', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:01:30', host: 'web-srv01', source: 'access.log', action: 'page_view', user: 'jsmith', status: 'success', src_ip: '192.168.1.100' },
        { _time: '2024-01-15 09:02:00', host: 'db-srv01', source: 'mysql.log', action: 'query', user: 'webapp', status: 'success', src_ip: '192.168.1.50' },
        { _time: '2024-01-15 09:02:45', host: 'web-srv01', source: 'access.log', action: 'login', user: 'mjohnson', status: 'success', src_ip: '192.168.1.105' },
        { _time: '2024-01-15 09:03:00', host: 'firewall', source: 'traffic.log', action: 'block', user: '-', status: 'denied', src_ip: '185.234.72.19' },
        { _time: '2024-01-15 09:03:01', host: 'firewall', source: 'traffic.log', action: 'block', user: '-', status: 'denied', src_ip: '185.234.72.19' },
        { _time: '2024-01-15 09:03:30', host: 'web-srv01', source: 'access.log', action: 'file_download', user: 'jsmith', status: 'success', src_ip: '192.168.1.100' },
        { _time: '2024-01-15 09:04:00', host: 'mail-srv', source: 'smtp.log', action: 'send', user: 'mjohnson', status: 'success', src_ip: '192.168.1.105' },
        { _time: '2024-01-15 09:05:00', host: 'web-srv01', source: 'access.log', action: 'login', user: 'root', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:05:01', host: 'web-srv01', source: 'access.log', action: 'login', user: 'administrator', status: 'failure', src_ip: '45.33.32.156' },
        { _time: '2024-01-15 09:06:00', host: 'dns-srv', source: 'query.log', action: 'lookup', user: '-', status: 'success', src_ip: '192.168.1.100' },
        { _time: '2024-01-15 09:07:00', host: 'web-srv02', source: 'access.log', action: 'login', user: 'agarcia', status: 'success', src_ip: '192.168.1.110' },
        { _time: '2024-01-15 09:08:00', host: 'firewall', source: 'traffic.log', action: 'allow', user: '-', status: 'allowed', src_ip: '192.168.1.100' },
        { _time: '2024-01-15 09:09:00', host: 'web-srv01', source: 'error.log', action: 'error', user: '-', status: 'error', src_ip: '-' },
        { _time: '2024-01-15 09:10:00', host: 'db-srv01', source: 'mysql.log', action: 'query', user: 'webapp', status: 'success', src_ip: '192.168.1.50' }
    ],

    challenges: [
        {
            id: 1,
            title: 'Find Failed Logins',
            description: 'Write a query to find all failed login attempts.',
            hint: 'Filter by action and status fields',
            expectedKeywords: ['status', 'failure', 'login'],
            expectedResultCount: 7,
            validateQuery: (query) => {
                const q = query.toLowerCase();
                return (q.includes('status') && q.includes('failure')) ||
                    (q.includes('action') && q.includes('login') && q.includes('fail'));
            },
            sampleAnswer: 'index=main action=login status=failure'
        },
        {
            id: 2,
            title: 'Count by Source IP',
            description: 'Find the top source IPs by event count. Which IP has the most events?',
            hint: 'Use stats count by src_ip',
            expectedKeywords: ['stats', 'count', 'src_ip'],
            expectedResultCount: null,
            validateQuery: (query) => {
                const q = query.toLowerCase();
                return q.includes('stats') && q.includes('count') && q.includes('src_ip');
            },
            sampleAnswer: 'index=main | stats count by src_ip | sort -count'
        },
        {
            id: 3,
            title: 'Identify Attack Source',
            description: 'Find the IP address that attempted the most failed logins (potential brute force attack).',
            hint: 'Combine filtering with stats',
            expectedKeywords: ['status', 'failure', 'stats', 'src_ip'],
            expectedResultCount: null,
            validateQuery: (query) => {
                const q = query.toLowerCase();
                return q.includes('fail') && q.includes('stats') && q.includes('src_ip');
            },
            sampleAnswer: 'index=main action=login status=failure | stats count by src_ip | sort -count'
        },
        {
            id: 4,
            title: 'Firewall Blocks',
            description: 'Find all events blocked by the firewall.',
            hint: 'Check the host and action fields',
            expectedKeywords: ['firewall', 'block'],
            expectedResultCount: 2,
            validateQuery: (query) => {
                const q = query.toLowerCase();
                return (q.includes('firewall') || q.includes('host=firewall')) &&
                    (q.includes('block') || q.includes('denied'));
            },
            sampleAnswer: 'index=main host=firewall action=block'
        },
        {
            id: 5,
            title: 'User Activity Timeline',
            description: 'Show all actions performed by user "jsmith" in chronological order.',
            hint: 'Filter by user and sort by time',
            expectedKeywords: ['user', 'jsmith'],
            expectedResultCount: 3,
            validateQuery: (query) => {
                const q = query.toLowerCase();
                return q.includes('user') && q.includes('jsmith');
            },
            sampleAnswer: 'index=main user=jsmith | sort _time'
        },
        {
            id: 6,
            title: 'Multi-Host Attack Detection',
            description: 'Find failed logins targeting multiple usernames from the same source IP (credential stuffing).',
            hint: 'Use stats with dc (distinct count) for users',
            expectedKeywords: ['stats', 'dc', 'user', 'src_ip'],
            expectedResultCount: null,
            validateQuery: (query) => {
                const q = query.toLowerCase();
                return q.includes('fail') && (q.includes('dc(') || q.includes('distinct')) && q.includes('src_ip');
            },
            sampleAnswer: 'index=main action=login status=failure | stats dc(user) as unique_users count by src_ip | where unique_users > 1'
        }
    ],

    render() {
        this.currentChallenge = 0;
        this.score = 0;
        this.results = [];

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">Splunk Query Challenge</h2>
                <div class="simulation-timer">
                    Challenge <span id="challenge-counter">1</span> of ${this.challenges.length}
                </div>
            </div>
            
            <div class="simulation-instructions" style="background: rgba(178, 77, 255, 0.1); border-color: rgba(178, 77, 255, 0.3);">
                <h4 style="color: var(--purple);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                        <polyline points="16 18 22 12 16 6"/>
                        <polyline points="8 6 2 12 8 18"/>
                    </svg>
                    Splunk Query Practice
                </h4>
                <p>Write SPL (Splunk Processing Language) queries to analyze security logs. You'll work with common search commands like <code>search</code>, <code>stats</code>, <code>where</code>, and <code>sort</code>.</p>
            </div>
            
            <div class="simulation-content" id="splunk-content">
                ${this.renderChallenge(0)}
            </div>
            
            <div class="simulation-actions">
                <button class="btn btn-outline" onclick="exitSimulation()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="19" y1="12" x2="5" y2="12"/>
                        <polyline points="12 19 5 12 12 5"/>
                    </svg>
                    Exit
                </button>
                <div class="score-display-inline" style="color: var(--purple); font-family: var(--font-display);">
                    Score: <span id="splunk-score">0</span> / ${this.maxScore}
                </div>
            </div>
        `;
    },

    renderChallenge(index) {
        const challenge = this.challenges[index];
        const result = this.results.find(r => r.challengeId === challenge.id);

        return `
            <div class="splunk-challenge">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
                    <!-- Left: Challenge & Query Input -->
                    <div>
                        <div class="challenge-card" style="background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; margin-bottom: 20px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                                <h3 style="color: var(--purple); margin: 0;">Challenge ${index + 1}: ${challenge.title}</h3>
                                <span style="background: rgba(178, 77, 255, 0.2); color: var(--purple); padding: 4px 12px; border-radius: 12px; font-size: 0.8rem;">100 pts</span>
                            </div>
                            <p style="color: var(--text-secondary); margin-bottom: 16px;">${challenge.description}</p>
                            <div style="background: rgba(0, 245, 255, 0.05); border: 1px solid rgba(0, 245, 255, 0.2); border-radius: 8px; padding: 12px;">
                                <span style="color: var(--cyan); font-size: 0.85rem;">💡 Hint: ${challenge.hint}</span>
                            </div>
                        </div>
                        
                        <div class="query-input-area" style="background: #0a0a0a; border-radius: 12px; border: 1px solid var(--border-color); overflow: hidden;">
                            <div style="background: #1a1a1a; padding: 12px 16px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 8px;">
                                <span style="color: var(--green);">▶</span>
                                <span style="color: var(--text-secondary); font-size: 0.85rem;">SPL Query Editor</span>
                            </div>
                            <div style="padding: 16px;">
                                <textarea 
                                    id="query-input" 
                                    placeholder="index=main | your query here..."
                                    style="width: 100%; height: 100px; background: transparent; border: none; color: var(--text-primary); font-family: 'Monaco', 'Consolas', monospace; font-size: 0.9rem; resize: none; outline: none;"
                                    ${result ? 'disabled' : ''}
                                >${result ? result.query : ''}</textarea>
                            </div>
                            <div style="padding: 12px 16px; border-top: 1px solid var(--border-color); display: flex; gap: 12px;">
                                ${result ? `
                                    <div style="flex: 1; padding: 10px 16px; border-radius: 8px; background: ${result.correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 217, 61, 0.1)'}; color: ${result.correct ? 'var(--green)' : 'var(--yellow)'};">
                                        ${result.correct ? '✓ Correct! +100 points' : `⚠ Partial credit: +${result.points} points`}
                                    </div>
                                    ${index < this.challenges.length - 1 ? `
                                        <button class="btn btn-primary" onclick="SplunkQuerySimulation.nextChallenge()">
                                            Next Challenge
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                                <line x1="5" y1="12" x2="19" y2="12"/>
                                                <polyline points="12 5 19 12 12 19"/>
                                            </svg>
                                        </button>
                                    ` : `
                                        <button class="btn btn-primary" onclick="SplunkQuerySimulation.complete()">
                                            Finish
                                        </button>
                                    `}
                                ` : `
                                    <button class="btn btn-outline" onclick="SplunkQuerySimulation.showHint()">
                                        Show Sample
                                    </button>
                                    <button class="btn btn-primary" onclick="SplunkQuerySimulation.runQuery()" style="flex: 1;">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                            <polygon points="5 3 19 12 5 21 5 3"/>
                                        </svg>
                                        Run Query
                                    </button>
                                `}
                            </div>
                        </div>
                    </div>
                    
                    <!-- Right: Sample Data & Results -->
                    <div>
                        <div style="background: #0a0a0a; border-radius: 12px; border: 1px solid var(--border-color); overflow: hidden; max-height: 500px;">
                            <div style="background: #1a1a1a; padding: 12px 16px; border-bottom: 1px solid var(--border-color);">
                                <span style="color: var(--text-secondary); font-size: 0.85rem;">📊 Sample Data (index=main)</span>
                            </div>
                            <div style="overflow-x: auto; max-height: 440px; overflow-y: auto;">
                                <table style="width: 100%; border-collapse: collapse; font-family: 'Monaco', 'Consolas', monospace; font-size: 0.75rem;">
                                    <thead>
                                        <tr style="background: var(--bg-tertiary);">
                                            <th style="padding: 8px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">_time</th>
                                            <th style="padding: 8px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">host</th>
                                            <th style="padding: 8px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">action</th>
                                            <th style="padding: 8px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">user</th>
                                            <th style="padding: 8px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">status</th>
                                            <th style="padding: 8px 12px; text-align: left; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">src_ip</th>
                                        </tr>
                                    </thead>
                                    <tbody id="data-tbody">
                                        ${this.sampleData.slice(0, 12).map(row => `
                                            <tr style="border-bottom: 1px solid var(--border-color);">
                                                <td style="padding: 6px 12px; color: var(--text-muted);">${row._time.split(' ')[1]}</td>
                                                <td style="padding: 6px 12px; color: var(--cyan);">${row.host}</td>
                                                <td style="padding: 6px 12px; color: var(--text-primary);">${row.action}</td>
                                                <td style="padding: 6px 12px; color: var(--purple);">${row.user}</td>
                                                <td style="padding: 6px 12px; color: ${row.status === 'failure' || row.status === 'denied' ? 'var(--red)' : 'var(--green)'};">${row.status}</td>
                                                <td style="padding: 6px 12px; color: var(--text-secondary);">${row.src_ip}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <div style="text-align: center; padding: 8px; color: var(--text-muted); font-size: 0.8rem;">
                            Showing 12 of ${this.sampleData.length} events
                        </div>
                    </div>
                </div>
                
                <!-- Query Results Area -->
                <div id="query-results" style="margin-top: 20px; display: none;">
                    <!-- Populated by runQuery() -->
                </div>
            </div>
        `;
    },

    init() {
        // Nothing special needed
    },

    runQuery() {
        const queryInput = document.getElementById('query-input');
        const query = queryInput.value.trim();

        if (!query) {
            this.showError('Please enter a query');
            return;
        }

        const challenge = this.challenges[this.currentChallenge];
        const resultsDiv = document.getElementById('query-results');

        // Simulate query execution
        const isValid = challenge.validateQuery(query);
        const filteredData = this.simulateQuery(query);

        // Calculate score
        let points = 0;
        let correct = false;

        if (isValid) {
            points = 100;
            correct = true;
        } else {
            // Partial credit for partially correct queries
            const keywordsFound = challenge.expectedKeywords.filter(kw =>
                query.toLowerCase().includes(kw.toLowerCase())
            ).length;
            points = Math.round((keywordsFound / challenge.expectedKeywords.length) * 50);
        }

        this.score += points;
        this.results.push({
            challengeId: challenge.id,
            query: query,
            correct: correct,
            points: points
        });

        // Update score display
        document.getElementById('splunk-score').textContent = this.score;

        // Show results
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div style="background: #0a0a0a; border-radius: 12px; border: 1px solid ${correct ? 'var(--green)' : 'var(--yellow)'}; overflow: hidden;">
                <div style="background: ${correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 217, 61, 0.1)'}; padding: 12px 16px; border-bottom: 1px solid var(--border-color);">
                    <span style="color: ${correct ? 'var(--green)' : 'var(--yellow)'};">
                        ${correct ? '✓ Query executed successfully!' : '⚠ Query could be improved'}
                    </span>
                    <span style="float: right; color: var(--text-muted);">${filteredData.length} results</span>
                </div>
                <div style="max-height: 200px; overflow-y: auto;">
                    <table style="width: 100%; border-collapse: collapse; font-family: 'Monaco', 'Consolas', monospace; font-size: 0.75rem;">
                        <thead>
                            <tr style="background: var(--bg-tertiary);">
                                ${Object.keys(filteredData[0] || this.sampleData[0]).map(key => `
                                    <th style="padding: 8px 12px; text-align: left; color: var(--cyan); border-bottom: 1px solid var(--border-color);">${key}</th>
                                `).join('')}
                            </tr>
                        </thead>
                        <tbody>
                            ${filteredData.slice(0, 10).map(row => `
                                <tr style="border-bottom: 1px solid var(--border-color);">
                                    ${Object.values(row).map(val => `
                                        <td style="padding: 6px 12px; color: var(--text-primary);">${val}</td>
                                    `).join('')}
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ${!correct ? `
                    <div style="padding: 12px 16px; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 0.85rem;">
                        <strong>Suggested query:</strong> <code style="color: var(--cyan);">${challenge.sampleAnswer}</code>
                    </div>
                ` : ''}
            </div>
        `;

        // Re-render challenge area to show completion state
        document.getElementById('splunk-content').innerHTML = this.renderChallenge(this.currentChallenge);
        document.getElementById('query-results').innerHTML = resultsDiv.innerHTML;
        document.getElementById('query-results').style.display = 'block';
    },

    simulateQuery(query) {
        const q = query.toLowerCase();
        let results = [...this.sampleData];

        // Simple query simulation
        if (q.includes('status=failure') || q.includes('status="failure"')) {
            results = results.filter(r => r.status === 'failure');
        }
        if (q.includes('status=success') || q.includes('status="success"')) {
            results = results.filter(r => r.status === 'success');
        }
        if (q.includes('action=login')) {
            results = results.filter(r => r.action === 'login');
        }
        if (q.includes('action=block')) {
            results = results.filter(r => r.action === 'block');
        }
        if (q.includes('host=firewall')) {
            results = results.filter(r => r.host === 'firewall');
        }
        if (q.includes('user=jsmith') || q.includes('user="jsmith"')) {
            results = results.filter(r => r.user === 'jsmith');
        }

        // Stats aggregation simulation
        if (q.includes('stats') && q.includes('count') && q.includes('src_ip')) {
            const counts = {};
            results.forEach(r => {
                counts[r.src_ip] = (counts[r.src_ip] || 0) + 1;
            });
            results = Object.entries(counts).map(([ip, count]) => ({
                src_ip: ip,
                count: count
            })).sort((a, b) => b.count - a.count);
        }

        // DC (distinct count) simulation
        if (q.includes('dc(') || q.includes('distinct')) {
            const byIp = {};
            results.forEach(r => {
                if (!byIp[r.src_ip]) byIp[r.src_ip] = new Set();
                byIp[r.src_ip].add(r.user);
            });
            results = Object.entries(byIp).map(([ip, users]) => ({
                src_ip: ip,
                unique_users: users.size,
                count: this.sampleData.filter(d => d.src_ip === ip).length
            })).sort((a, b) => b.unique_users - a.unique_users);
        }

        return results;
    },

    showHint() {
        const challenge = this.challenges[this.currentChallenge];
        const queryInput = document.getElementById('query-input');
        queryInput.value = challenge.sampleAnswer;
        queryInput.style.color = 'var(--yellow)';
    },

    showError(message) {
        const resultsDiv = document.getElementById('query-results');
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div style="background: rgba(255, 56, 96, 0.1); border: 1px solid var(--red); border-radius: 8px; padding: 16px; color: var(--red);">
                ⚠ ${message}
            </div>
        `;
    },

    nextChallenge() {
        this.currentChallenge++;
        document.getElementById('challenge-counter').textContent = this.currentChallenge + 1;
        document.getElementById('splunk-content').innerHTML = this.renderChallenge(this.currentChallenge);
    },

    complete() {
        const feedback = this.results.map((result, idx) => {
            const challenge = this.challenges[idx];
            return {
                correct: result.correct,
                title: `Challenge ${idx + 1}: ${challenge.title}`,
                explanation: result.correct
                    ? 'Excellent query - you found the right approach!'
                    : `Better query: ${challenge.sampleAnswer}`
            };
        });

        completeSimulation('log-analysis', this.score, this.maxScore, feedback);
    }
};

// Export for global access
window.SplunkQuerySimulation = SplunkQuerySimulation;
