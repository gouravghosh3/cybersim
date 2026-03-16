/**
 * CyberShield - SOC Analyst Competition Platform
 * Main Application Logic
 */

// ============================================
// State Management
// ============================================
const AppState = {
    currentView: 'dashboard',
    currentSimulation: null,
    progress: {
        'log-analysis': { completed: false, score: 0, attempts: 0, completedAt: null },
        'phishing': { completed: false, score: 0, attempts: 0, completedAt: null },
        'incident-response': { completed: false, score: 0, attempts: 0, completedAt: null },
        'network-analysis': { completed: false, score: 0, attempts: 0, completedAt: null },
        'threat-hunting': { completed: false, score: 0, attempts: 0, completedAt: null },
        'threat-stacking': { completed: false, score: 0, attempts: 0, completedAt: null },
        'mystery-challenge': { completed: false, score: 0, attempts: 0, completedAt: null },
        'quickfire': { completed: false, score: 0, attempts: 0, completedAt: null }
    },
    totalScore: 0,
    timeSpent: 0,
    startTime: null,
    simulationStartTime: null,
    consecutiveHighScores: 0,
    achievements: [],
    // Competition fields
    employeeId: null,
    displayName: null,
    alias: null,
    competitionStartTime: null
};

// ============================================
// MITRE ATT&CK Data
// ============================================
const MITRE_DATA = {
    'log-analysis': {
        id: 'T1110', name: 'Brute Force', tactic: 'Credential Access',
        description: 'Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.',
        stat: 'In 2024, 23% of breaches started with credential stuffing or brute force against external-facing systems.'
    },
    'phishing': {
        id: 'T1566', name: 'Phishing', tactic: 'Initial Access',
        description: 'Adversaries may send phishing messages to gain access to victim systems. Messages often contain malicious links or attachments.',
        stat: 'Over 90% of targeted cyber attacks begin with a spear-phishing email targeting employees.'
    },
    'incident-response': {
        id: 'Multiple', name: 'Incident Containment Pipeline', tactic: 'Response',
        description: 'Effective incident response disrupts the kill chain. Rapid isolation, eradication, and recovery prevents initial access from becoming exfiltration.',
        stat: 'The global average time to identify and contain a data breach is 277 days. You did it in minutes.'
    },
    'network-analysis': {
        id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control',
        description: 'Adversaries may communicate using typical application layer protocols (HTTPS, DNS) to avoid detection/network filtering by blending in with existing traffic.',
        stat: 'C2 beacons mimicking HTTPS or DNS traffic account for a majority of successful data exfiltration channels.'
    },
    'threat-hunting': {
        id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion',
        description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.',
        stat: 'Attackers frequently disguise malicious processes as "svchost.exe" or "explorer.exe" to hide in plain sight.'
    },
    'threat-stacking': {
        id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution',
        description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
        stat: 'Low-frequency, highly unique command executions often indicate interactive attacker tooling via PowerShell or cmd.exe.'
    },
    'mystery-challenge': {
        id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Execution',
        description: 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',
        stat: 'Scheduled tasks are frequently used for persistence and privilege escalation, often remaining undetected for months.'
    },
    'quickfire': {
        id: 'Multiple', name: 'General Cyber Knowledge', tactic: 'Foundations',
        description: 'A strong understanding of cybersecurity fundamentals (CIA triad, common protocols, basic attacks) is critical for effective defense.',
        stat: 'Continuous learning and reinforcing fundamentals reduces human error, which is a factor in 74% of all breaches.'
    }
};

// ============================================
// Initialization
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Initialize database layer
    GameDB.init();

    // Show registration screen (game starts after registration)
    CompetitionManager.showRegistration();
});

/**
 * Called by CompetitionManager after successful registration
 * @param {Object} playerData - Player data from GameDB
 */
function startGameWithPlayer(playerData) {
    // Merge player data into AppState
    AppState.employeeId = playerData.employeeId;
    AppState.displayName = playerData.displayName;
    AppState.alias = playerData.alias;
    AppState.competitionStartTime = playerData.competitionStartTime;

    if (playerData.progress) {
        Object.assign(AppState.progress, playerData.progress);
    }
    AppState.totalScore = playerData.totalScore || 0;
    AppState.timeSpent = playerData.timeSpent || 0;
    AppState.achievements = playerData.achievements || [];

    initNavigation();
    updateUI();
    initProgressView();
    startTimeTracking();
}

function loadProgress() {
    const saved = localStorage.getItem('cybersim-progress');
    if (saved) {
        const parsed = JSON.parse(saved);
        Object.assign(AppState, parsed);
    }
}

function saveProgress() {
    const playerData = {
        employeeId: AppState.employeeId,
        displayName: AppState.displayName,
        alias: AppState.alias,
        progress: AppState.progress,
        totalScore: AppState.totalScore,
        timeSpent: AppState.timeSpent,
        achievements: AppState.achievements,
        competitionStartTime: AppState.competitionStartTime,
        lastUpdated: new Date().toISOString()
    };
    // Save to GameDB (async, fire-and-forget for UI responsiveness)
    GameDB.savePlayer(playerData).catch(err => {
        console.error('[App] Save failed:', err);
    });
    // Also update CompetitionManager's reference
    if (CompetitionManager.playerData) {
        Object.assign(CompetitionManager.playerData, playerData);
    }
}

function startTimeTracking() {
    AppState.startTime = Date.now();
    setInterval(() => {
        const sessionTime = Math.floor((Date.now() - AppState.startTime) / 60000);
        const totalMinutes = AppState.timeSpent + sessionTime;
        document.getElementById('time-spent').textContent = formatTime(totalMinutes);
    }, 60000);
}

function formatTime(minutes) {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
}

// ============================================
// Navigation
// ============================================
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const view = item.dataset.view;
            if (!view) return; // Let external links (e.g. Leaderboard) navigate normally
            e.preventDefault();
            showView(view);
        });
    });

    document.getElementById('reset-progress').addEventListener('click', resetProgress);
}

function showView(viewName) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewName);
    });

    // Update views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
    });
    document.getElementById(`${viewName}-view`).classList.add('active');

    // Update header title
    const titles = {
        'dashboard': 'Dashboard',
        'simulations': 'Simulations',
        'progress': 'Your Progress',
        'simulation': 'Active Simulation'
    };
    document.getElementById('view-title').textContent = titles[viewName] || viewName;

    AppState.currentView = viewName;
}

// ============================================
// UI Updates
// ============================================
function updateUI() {
    updateScores();
    updateProgressCards();
    updateRank();
    updateAccuracy();
}

function updateScores() {
    document.getElementById('total-score').textContent = AppState.totalScore.toLocaleString();

    const completed = Object.values(AppState.progress).filter(p => p.completed).length;
    document.getElementById('completed-count').textContent = `${completed}/8`;
}

function updateProgressCards() {
    Object.entries(AppState.progress).forEach(([key, data]) => {
        const progressEl = document.getElementById(`${key}-progress`);
        const card = document.querySelector(`[data-simulation="${key}"]`);

        if (progressEl && card) {
            const progressText = card.querySelector('.progress-text');
            const btn = card.querySelector('.btn-card');

            if (data.completed) {
                progressEl.style.width = '100%';
                progressText.textContent = `Completed - ${data.score} pts`;
                btn.textContent = 'Retry Simulation';
            } else if (data.attempts > 0) {
                progressEl.style.width = '50%';
                progressText.textContent = 'In Progress';
            }
        }
    });
}

function updateRank() {
    const ranks = [
        { threshold: 0, name: 'Novice' },
        { threshold: 500, name: 'Analyst I' },
        { threshold: 1000, name: 'Analyst II' },
        { threshold: 1500, name: 'Senior Analyst' },
        { threshold: 2000, name: 'Expert' },
        { threshold: 2500, name: 'Master' }
    ];

    const rank = ranks.reduce((acc, r) => AppState.totalScore >= r.threshold ? r : acc);
    document.getElementById('rank-level').textContent = rank.name;
}

function updateAccuracy() {
    const simulations = Object.values(AppState.progress);
    const completed = simulations.filter(s => s.completed);

    if (completed.length === 0) {
        document.getElementById('accuracy-rate').textContent = '0%';
        return;
    }

    // Calculate based on average score percentage
    const maxScores = { 'log-analysis': 500, 'phishing': 300, 'incident-response': 750, 'network-analysis': 600, 'threat-hunting': 800, 'threat-stacking': 800, 'mystery-challenge': 400, 'quickfire': 200 };
    let totalPercentage = 0;

    Object.entries(AppState.progress).forEach(([key, data]) => {
        if (data.completed && maxScores[key]) {
            totalPercentage += (data.score / maxScores[key]) * 100;
        }
    });

    const avgAccuracy = Math.round(totalPercentage / completed.length);
    document.getElementById('accuracy-rate').textContent = `${avgAccuracy}%`;
}

// ============================================
// Progress View
// ============================================
function initProgressView() {
    renderProgressList();
    renderAchievements();
    updateProgressRing();
    renderRadarChart();

    const certBtn = document.getElementById('btn-download-cert');
    if (certBtn) {
        // Show button if at least 1 simulation is completed
        const completed = Object.values(AppState.progress).filter(p => p.completed).length;
        certBtn.style.display = completed > 0 ? 'flex' : 'none';
        certBtn.style.alignItems = 'center';
        certBtn.style.gap = '8px';
    }
}

function renderProgressList() {
    const container = document.getElementById('progress-list');
    const simulations = [
        { id: 'log-analysis', name: 'Log Analysis', color: 'cyan', maxScore: 500 },
        { id: 'phishing', name: 'Phishing Detection', color: 'purple', maxScore: 300 },
        { id: 'incident-response', name: 'Incident Response', color: 'orange', maxScore: 750 },
        { id: 'network-analysis', name: 'Network Traffic Analysis', color: 'green', maxScore: 600 },
        { id: 'threat-hunting', name: 'Threat Hunting: Clustering', color: 'orange', maxScore: 800 },
        { id: 'threat-stacking', name: 'Threat Hunting: Stacking', color: 'red', maxScore: 800 },
        { id: 'mystery-challenge', name: 'Live Breach Response', color: 'red', maxScore: 400 },
        { id: 'quickfire', name: 'Quick-Fire Round', color: 'yellow', maxScore: 200 }
    ];

    container.innerHTML = simulations.map(sim => {
        const progress = AppState.progress[sim.id];
        const status = progress.completed ? `${progress.score}/${sim.maxScore}` : 'Not completed';

        return `
            <div class="progress-item">
                <div class="progress-item-info">
                    <div class="progress-item-icon ${sim.color}" style="background: var(--${sim.color}-glow);">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--${sim.color});">
                            ${progress.completed ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>' : '<circle cx="12" cy="12" r="10"/>'}
                        </svg>
                    </div>
                    <span class="progress-item-name">${sim.name}</span>
                </div>
                <span class="progress-item-score">${status}</span>
            </div>
        `;
    }).join('');
}

function renderAchievements() {
    const container = document.getElementById('achievements-grid');
    const achievements = [
        { id: 'first-blood', name: 'First Blood', desc: 'Complete your first simulation', icon: '🎯', tier: 'bronze' },
        { id: 'log-master', name: 'Log Master', desc: 'Score 100% on Log Analysis', icon: '📋', tier: 'gold' },
        { id: 'phish-finder', name: 'Phish Finder', desc: 'Identify all phishing emails', icon: '🎣', tier: 'silver' },
        { id: 'responder', name: 'First Responder', desc: 'Complete Incident Response', icon: '🚨', tier: 'bronze' },
        { id: 'network-ninja', name: 'Network Ninja', desc: 'Perfect Network Analysis', icon: '🌐', tier: 'gold' },
        { id: 'completionist', name: 'Completionist', desc: 'Complete all simulations', icon: '🏆', tier: 'gold' },
        { id: 'perfectionist', name: 'Perfectionist', desc: 'Score 100% on all simulations', icon: '⭐', tier: 'gold' },
        { id: 'dedicated', name: 'Dedicated', desc: 'Spend 1 hour training', icon: '⏰', tier: 'silver' }
    ];

    container.innerHTML = achievements.map(ach => {
        const unlocked = AppState.achievements.includes(ach.id);

        return `
            <div class="achievement-card ${unlocked ? '' : 'locked'}">
                <div class="achievement-icon ${unlocked ? ach.tier : 'locked'}">${ach.icon}</div>
                <div class="achievement-name">${ach.name}</div>
                <div class="achievement-desc">${ach.desc}</div>
            </div>
        `;
    }).join('');
}

function updateProgressRing() {
    const completed = Object.values(AppState.progress).filter(p => p.completed).length;
    const percentage = (completed / 8) * 100;

    document.getElementById('overall-percentage').textContent = `${Math.round(percentage)}%`;

    const ring = document.getElementById('overall-progress-ring');
    if (ring) {
        const circumference = 2 * Math.PI * 45;
        const offset = circumference - (percentage / 100) * circumference;
        ring.style.strokeDashoffset = offset;
        ring.style.stroke = 'url(#progressGradient)';

        // Add gradient definition if not exists
        if (!document.getElementById('progressGradient')) {
            const svg = ring.closest('svg');
            const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
            defs.innerHTML = `
                <linearGradient id="progressGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" style="stop-color:#00f5ff"/>
                    <stop offset="100%" style="stop-color:#b24dff"/>
                </linearGradient>
            `;
            svg.insertBefore(defs, svg.firstChild);
        }
    }
}

function getRadarPolygonPoints(scores, radius, center) {
    const points = [];
    for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i - (Math.PI / 2);
        const r = radius * (scores[i] || 0.05); // min 5% for visibility
        points.push(`${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`);
    }
    return points.join(' ');
}

function renderRadarChart(containerId = 'radar-chart-container', size = 250) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Define axes and get scores (normalized 0 to 1)
    const axes = [
        { label: 'Detection', key: 'log-analysis', max: 500 },
        { label: 'Proactive', key: 'threat-hunting', max: 800 },
        { label: 'Forensics', key: 'network-analysis', max: 600 },
        { label: 'Data Analysis', key: 'threat-stacking', max: 800 },
        { label: 'Response', key: 'incident-response', max: 750 },
        { label: 'Awareness', key: 'phishing', max: 300 }
    ];

    const scores = axes.map(axis => {
        const progress = AppState.progress[axis.key];
        return progress && progress.completed ? (progress.score / axis.max) : 0.0;
    });

    const center = size / 2;
    const radius = center * 0.65; // leave room for labels

    // Draw background web
    const levels = 4;
    let webSVG = '';
    for (let level = 1; level <= levels; level++) {
        const r = radius * (level / levels);
        const pts = getRadarPolygonPoints([1,1,1,1,1,1].map(() => level/levels), radius, center);
        webSVG += `<polygon points="${pts}" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>`;
    }

    // Draw axes
    let axesSVG = '';
    let labelsSVG = '';
    for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i - (Math.PI / 2);
        const x2 = center + radius * Math.cos(angle);
        const y2 = center + radius * Math.sin(angle);
        axesSVG += `<line x1="${center}" y1="${center}" x2="${x2}" y2="${y2}" stroke="rgba(255,255,255,0.2)" stroke-width="1"/>`;

        // Labels
        const lx = center + (radius * 1.25) * Math.cos(angle);
        const ly = center + (radius * 1.25) * Math.sin(angle);
        let anchor = 'middle';
        if (Math.abs(Math.cos(angle)) > 0.1) {
            anchor = Math.cos(angle) > 0 ? 'start' : 'end';
        }
        labelsSVG += `<text x="${lx}" y="${ly + 4}" text-anchor="${anchor}" fill="var(--text-secondary)" font-size="10px" font-family="var(--font-display)" font-weight="bold">${axes[i].label}</text>`;
    }

    // Draw data polygon
    const dataPts = getRadarPolygonPoints(scores, radius, center);

    const svg = `
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            <defs>
                <linearGradient id="radarFill" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:rgba(0,245,255,0.4)" />
                    <stop offset="100%" style="stop-color:rgba(178,77,255,0.4)" />
                </linearGradient>
            </defs>
            ${webSVG}
            ${axesSVG}
            ${labelsSVG}
            <polygon points="${dataPts}" fill="url(#radarFill)" stroke="var(--cyan)" stroke-width="2" stroke-linejoin="round"/>
            ${scores.map((s, i) => {
                const angle = (Math.PI / 3) * i - (Math.PI / 2);
                const r = radius * (s || 0.05);
                const cx = center + r * Math.cos(angle);
                const cy = center + r * Math.sin(angle);
                return `<circle cx="${cx}" cy="${cy}" r="4" fill="var(--yellow)" stroke="var(--bg-card)" stroke-width="1"/>`;
            }).join('')}
        </svg>
    `;

    container.innerHTML = svg;
}

function generateTakeawayCard() {
    let cardOverlay = document.getElementById('takeaway-overlay');
    if (!cardOverlay) {
        cardOverlay = document.createElement('div');
        cardOverlay.id = 'takeaway-overlay';
        cardOverlay.className = 'modal-overlay';
        document.body.appendChild(cardOverlay);
    }

    const completed = Object.values(AppState.progress).filter(p => p.completed).length;
    const completeness = Math.round((completed / 8) * 100);
    const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    const rank = document.getElementById('rank-level')?.textContent || 'Novice';
    const accuracy = document.getElementById('accuracy-rate')?.textContent || '0%';

    // Find practiced MITRE tactics
    const practicedTactics = Object.entries(AppState.progress)
        .filter(([key, p]) => p.completed && MITRE_DATA[key])
        .map(([key]) => MITRE_DATA[key].id + ' - ' + MITRE_DATA[key].tactic);
    
    const uniqueTactics = [...new Set(practicedTactics)].slice(0, 5); // Take top 5 unique

    cardOverlay.innerHTML = `
        <div class="takeaway-card-container" style="background: linear-gradient(135deg, #090e17 0%, #151f32 100%); border: 2px solid var(--cyan); border-radius: 12px; width: 90%; max-width: 800px; padding: 40px; box-shadow: 0 0 50px rgba(0,245,255,0.15); display: flex; flex-direction: column; position: relative;">
            <button class="modal-close" onclick="document.getElementById('takeaway-overlay').classList.remove('active')" style="position: absolute; top: 20px; right: 20px;">&times;</button>
            
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 30px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 20px;">
                <div>
                    <h2 style="font-family: var(--font-display); color: var(--text-primary); margin: 0 0 8px 0; font-size: 2rem;">SOC Analyst Proficiency Report</h2>
                    <div style="color: var(--cyan); letter-spacing: 2px; font-weight: bold; font-size: 0.9rem;">OPERATION: CYBERSHIELD // JP MORGAN</div>
                </div>
                <div style="text-align: right;">
                    <div style="color: var(--text-muted); font-size: 0.9rem;">DATE ISSUED</div>
                    <div style="color: var(--text-secondary); font-weight: bold;">${dateStr}</div>
                </div>
            </div>

            <div style="display: flex; gap: 40px;">
                <div style="flex: 1;">
                    <div style="margin-bottom: 24px;">
                        <div style="color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 4px;">Analyst Designation</div>
                        <div style="color: var(--text-primary); font-size: 1.5rem; font-weight: bold;">${AppState.displayName || 'Unknown'}</div>
                        <div style="color: var(--text-secondary); font-family: monospace;">Alias: ${AppState.alias || '---'}</div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 30px;">
                        <div style="background: rgba(255,255,255,0.03); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 4px;">FINAL RANK</div>
                            <div style="color: var(--yellow); font-size: 1.4rem; font-weight: bold; font-family: var(--font-display);">${rank}</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.03); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 4px;">TOTAL SCORE</div>
                            <div style="color: var(--cyan); font-size: 1.4rem; font-weight: bold; font-family: var(--font-display);">${AppState.totalScore.toLocaleString()} pts</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.03); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 4px;">ACCURACY</div>
                            <div style="color: var(--green); font-size: 1.4rem; font-weight: bold; font-family: var(--font-display);">${accuracy}</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.03); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 4px;">COMPLETION</div>
                            <div style="color: var(--text-primary); font-size: 1.4rem; font-weight: bold; font-family: var(--font-display);">${completeness}%</div>
                        </div>
                    </div>

                    ${uniqueTactics.length > 0 ? `
                        <div>
                            <div style="color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 12px;">Validated MITRE ATT&CK Tactics</div>
                            <div style="display: flex; flex-direction: column; gap: 8px;">
                                ${uniqueTactics.map(t => `
                                    <div style="background: rgba(178,77,255,0.1); border: 1px solid rgba(178,77,255,0.3); color: var(--purple); padding: 6px 12px; border-radius: 4px; font-size: 0.85rem;">
                                        ${t}
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>

                <div style="flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; background: rgba(0,0,0,0.2); border-radius: 12px; padding: 20px;">
                    <div style="color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 20px; letter-spacing: 1px;">Skill Radar Analysis</div>
                    <div id="takeaway-radar-container" style="width: 250px; height: 250px;"></div>
                </div>
            </div>
            
            <div style="margin-top: 30px; text-align: center; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 20px; display: flex; justify-content: space-between; align-items: center;">
                <div style="font-family: monospace; color: var(--text-secondary); font-size: 0.8rem;">ID: ${Date.now().toString(16).toUpperCase()}-${AppState.employeeId || 'ANON'}</div>
                <button class="btn btn-primary" onclick="window.print()" style="padding: 10px 20px;">🖨️ Print / Save as PDF</button>
            </div>
        </div>
    `;

    cardOverlay.classList.add('active');
    
    // Defer rendering radar to next tick so container exists in DOM
    setTimeout(() => {
        renderRadarChart('takeaway-radar-container', 250);
    }, 50);
}

// ============================================
// Simulation Management
// ============================================
function startSimulation(simulationId) {
    AppState.currentSimulation = simulationId;
    AppState.simulationStartTime = Date.now();

    // Show simulation view
    document.querySelectorAll('.view').forEach(view => view.classList.remove('active'));
    document.getElementById('simulation-view').classList.add('active');
    document.getElementById('view-title').textContent = 'Active Simulation';

    // Load simulation content
    const container = document.getElementById('simulation-container');

    // Map splunk-query to log-analysis for progress tracking
    const progressKey = simulationId === 'splunk-query' ? 'log-analysis' : simulationId;

    switch (simulationId) {
        case 'log-analysis':
            container.innerHTML = LogAnalysisSimulation.render();
            LogAnalysisSimulation.init();
            break;
        case 'splunk-query':
            container.innerHTML = SplunkQuerySimulation.render();
            SplunkQuerySimulation.init();
            break;
        case 'phishing':
            container.innerHTML = PhishingSimulation.render();
            PhishingSimulation.init();
            break;
        case 'incident-response':
            container.innerHTML = IncidentResponseSimulation.render();
            IncidentResponseSimulation.init();
            break;
        case 'network-analysis':
            container.innerHTML = NetworkAnalysisSimulation.render();
            NetworkAnalysisSimulation.init();
            break;
        case 'threat-hunting':
            container.innerHTML = ThreatHuntingSimulation.render();
            ThreatHuntingSimulation.init();
            break;
        case 'threat-stacking':
            container.innerHTML = ThreatStackingSimulation.render();
            ThreatStackingSimulation.init();
            break;
        case 'mystery-challenge':
            container.innerHTML = MysteryChallenge.render();
            MysteryChallenge.init();
            break;
        case 'quickfire':
            container.innerHTML = QuickFireSimulation.render();
            QuickFireSimulation.init();
            break;
    }

    if (AppState.progress[progressKey]) {
        AppState.progress[progressKey].attempts++;
    }
    saveProgress();
}

const parTimes = {
    'log-analysis': 15,
    'phishing': 10,
    'incident-response': 20,
    'network-analysis': 15,
    'threat-hunting': 25,
    'threat-stacking': 25,
    'mystery-challenge': 2.5,
    'quickfire': 1.5
};

function completeSimulation(simulationId, score, maxScore, feedback) {
    // Check if competition is still active
    if (!CompetitionManager.isGameActive) {
        showView('simulations');
        return;
    }

    const progress = AppState.progress[simulationId];
    
    // Adaptive / Speed Scoring
    let timeMultiplier = 1.0;
    if (AppState.simulationStartTime && parTimes[simulationId]) {
        const timeTakenMin = (Date.now() - AppState.simulationStartTime) / 60000;
        const par = parTimes[simulationId];
        
        if (timeTakenMin <= par * 0.5) timeMultiplier = 1.5;
        else if (timeTakenMin <= par * 0.75) timeMultiplier = 1.25;
        else if (timeTakenMin <= par) timeMultiplier = 1.1;
    }
    
    let speedBonus = Math.round(score * timeMultiplier) - score;
    
    // Streak Bonus
    let streakBonus = 0;
    if ((score / maxScore) >= 0.7 && simulationId !== 'quickfire' && simulationId !== 'mystery-challenge') {
        AppState.consecutiveHighScores = (AppState.consecutiveHighScores || 0) + 1;
        if (AppState.consecutiveHighScores >= 3 && !progress.completed) {
            // Only award streak bonus once per simulation on successful completion
            streakBonus = 50;
        }
    } else if (simulationId !== 'quickfire' && simulationId !== 'mystery-challenge') {
        AppState.consecutiveHighScores = 0;
    }

    const finalScore = score + speedBonus + streakBonus;

    // Update progress
    progress.completed = true;
    progress.score = Math.max(progress.score, finalScore);
    progress.completedAt = new Date().toISOString();

    // Update total score
    AppState.totalScore = Object.values(AppState.progress).reduce((sum, p) => sum + p.score, 0);

    // Check achievements
    checkAchievements(simulationId, score, maxScore);

    // Save and update UI
    saveProgress();
    updateUI();
    initProgressView();

    // Show results modal
    showResultsModal(simulationId, finalScore, maxScore, feedback, score, speedBonus, streakBonus);
}

function checkAchievements(simulationId, score, maxScore) {
    const completed = Object.values(AppState.progress).filter(p => p.completed);

    // First Blood
    if (completed.length === 1 && !AppState.achievements.includes('first-blood')) {
        AppState.achievements.push('first-blood');
    }

    // Simulation-specific achievements
    if (score === maxScore) {
        const perfectAchievements = {
            'log-analysis': 'log-master',
            'phishing': 'phish-finder',
            'network-analysis': 'network-ninja'
        };
        if (perfectAchievements[simulationId] && !AppState.achievements.includes(perfectAchievements[simulationId])) {
            AppState.achievements.push(perfectAchievements[simulationId]);
        }
    }

    if (simulationId === 'incident-response' && !AppState.achievements.includes('responder')) {
        AppState.achievements.push('responder');
    }

    // Completionist
    if (completed.length === 6 && !AppState.achievements.includes('completionist')) {
        AppState.achievements.push('completionist');
    }

    // Perfectionist
    const allPerfect = Object.entries(AppState.progress).every(([id, p]) => {
        const maxScores = { 'log-analysis': 500, 'phishing': 300, 'incident-response': 750, 'network-analysis': 600, 'threat-hunting': 800, 'threat-stacking': 800 };
        return p.score === maxScores[id];
    });
    if (allPerfect && !AppState.achievements.includes('perfectionist')) {
        AppState.achievements.push('perfectionist');
    }
}

function exitSimulation() {
    AppState.currentSimulation = null;
    showView('simulations');
}

// ============================================
// Modal Management
// ============================================
function showResultsModal(simulationId, finalScore, maxScore, feedback, baseScore = finalScore, speedBonus = 0, streakBonus = 0) {
    const overlay = document.getElementById('modal-overlay');
    const body = document.getElementById('modal-body');
    const actionBtn = document.getElementById('modal-action');

    const percentage = Math.round((baseScore / maxScore) * 100);
    const correct = feedback.filter(f => f.correct).length;
    const incorrect = feedback.filter(f => !f.correct).length;

    let gradeClass = 'cyan';
    let gradeText = 'Excellent!';
    if (percentage < 50) {
        gradeClass = 'red';
        gradeText = 'Keep Practicing';
    } else if (percentage < 80) {
        gradeClass = 'yellow';
        gradeText = 'Good Work!';
    }

    body.innerHTML = `
        <div class="score-display">
            <div class="score-value">${finalScore}</div>
            <div style="color: var(--${gradeClass}); font-size: 1.2rem; font-weight: 600;">${gradeText}</div>
            <div class="score-breakdown">
                <div class="score-item">
                    <div class="score-item-value correct">${correct}</div>
                    <div class="score-item-label">Correct</div>
                </div>
                <div class="score-item">
                    <div class="score-item-value incorrect">${incorrect}</div>
                    <div class="score-item-label">Missed</div>
                </div>
                <div class="score-item">
                    <div class="score-item-value">${percentage}%</div>
                    <div class="score-item-label">Accuracy</div>
                </div>
            </div>
            ${(speedBonus > 0 || streakBonus > 0) ? `
                <div style="margin-top: 20px; font-size: 0.9rem; color: var(--text-secondary); background: rgba(0,0,0,0.2); padding: 10px; border-radius: 8px;">
                    <div>Base Score: <strong>${baseScore}</strong></div>
                    ${speedBonus > 0 ? `<div style="color: var(--cyan);">Speed Bonus: <strong>+${speedBonus}</strong></div>` : ''}
                    ${streakBonus > 0 ? `<div style="color: var(--yellow);">Streak Bonus: <strong>+${streakBonus}</strong> 🔥</div>` : ''}
                </div>
            ` : ''}
        </div>
        ${feedback.length > 0 ? `
            <div class="feedback-section">
                <h4 style="margin-bottom: 16px;">Feedback</h4>
                ${feedback.slice(0, 5).map(f => `
                    <div class="feedback-item ${f.correct ? 'correct' : 'missed'}">
                        <div class="feedback-title">${f.title}</div>
                        <div class="feedback-explanation">${f.explanation}</div>
                    </div>
                `).join('')}
            </div>
        ` : ''}
        ${MITRE_DATA[simulationId] ? `
            <div class="mitre-card" style="margin-top: 24px; padding: 20px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; text-align: left; position: relative;">
                <div style="position: absolute; top: -10px; right: 20px; background: var(--bg-card); padding: 0 10px; color: var(--cyan); font-family: var(--font-display); font-size: 0.8rem; font-weight: bold; letter-spacing: 2px;">INTEL DEBRIEF</div>
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                    <h4 style="color: var(--text-primary); margin: 0; font-size: 1.1rem;">${MITRE_DATA[simulationId].name}</h4>
                    <span style="background: rgba(0, 245, 255, 0.1); color: var(--cyan); padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold;">${MITRE_DATA[simulationId].id}</span>
                </div>
                <div style="color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 12px; letter-spacing: 1px;">Tactic: ${MITRE_DATA[simulationId].tactic}</div>
                <p style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5; margin-bottom: 16px;">${MITRE_DATA[simulationId].description}</p>
                <div style="border-top: 1px dashed rgba(255, 255, 255, 0.2); padding-top: 12px; font-style: italic; color: var(--text-muted); font-size: 0.9rem;">
                    💡 ${MITRE_DATA[simulationId].stat}
                </div>
            </div>
        ` : ''}
    `;

    actionBtn.textContent = 'Continue Training';
    actionBtn.onclick = () => {
        closeModal();
        showView('simulations');
    };

    overlay.classList.add('active');
}

function showModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal-overlay').classList.add('active');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('active');
}

// ============================================
// Reset Progress
// ============================================
function resetProgress() {
    if (confirm('Are you sure you want to reset all progress? This cannot be undone.')) {
        localStorage.removeItem('cybersim-progress');

        // Reset state
        AppState.progress = {
            'log-analysis': { completed: false, score: 0, attempts: 0 },
            'phishing': { completed: false, score: 0, attempts: 0 },
            'incident-response': { completed: false, score: 0, attempts: 0 },
            'network-analysis': { completed: false, score: 0, attempts: 0 },
            'threat-hunting': { completed: false, score: 0, attempts: 0 },
            'threat-stacking': { completed: false, score: 0, attempts: 0 },
            'mystery-challenge': { completed: false, score: 0, attempts: 0 },
            'quickfire': { completed: false, score: 0, attempts: 0 }
        };
        AppState.totalScore = 0;
        AppState.achievements = [];

        updateUI();
        initProgressView();

        // Reset progress bars visually
        document.querySelectorAll('.progress-fill').forEach(el => el.style.width = '0%');
        document.querySelectorAll('.progress-text').forEach(el => el.textContent = 'Not Started');
        document.querySelectorAll('.btn-card').forEach(el => el.textContent = 'Start Simulation');
    }
}

// Export for global access
window.showView = showView;
window.startSimulation = startSimulation;
window.completeSimulation = completeSimulation;
window.exitSimulation = exitSimulation;
window.closeModal = closeModal;
window.startGameWithPlayer = startGameWithPlayer;
