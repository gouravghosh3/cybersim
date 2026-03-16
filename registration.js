/**
 * Registration & Competition Flow
 * Handles player registration, competition timer, and session management
 */

const CompetitionManager = {
    COMPETITION_DURATION_MINUTES: 60,
    timerInterval: null,
    leaderboardInterval: null,
    isGameActive: false,
    mysteryUnlocked: false,
    playerData: null,

    // ============================================
    // Registration Screen
    // ============================================
    showRegistration() {
        const overlay = document.getElementById('registration-overlay');
        const empIdInput = document.getElementById('reg-employee-id');
        const empIdField = document.getElementById('reg-employee-field');

        // Auto-detect employee ID on SharePoint
        if (GameDB.isSharePoint()) {
            const currentUser = GameDB.getCurrentUser();
            if (currentUser) {
                empIdInput.value = currentUser;
                empIdInput.readOnly = true;
                empIdField.classList.add('auto-detected');
                document.getElementById('reg-auto-detect-badge').style.display = 'inline-flex';
            }
        }

        overlay.classList.add('active');
    },

    async handleRegistration() {
        const employeeId = document.getElementById('reg-employee-id').value.trim();
        const displayName = document.getElementById('reg-display-name').value.trim();
        const alias = document.getElementById('reg-alias').value.trim();
        const errorEl = document.getElementById('reg-error');
        const submitBtn = document.getElementById('reg-submit-btn');

        // Validation
        if (!employeeId) {
            errorEl.textContent = '⚠ Employee ID is required';
            errorEl.style.display = 'block';
            return;
        }
        if (!displayName) {
            errorEl.textContent = '⚠ Display name is required';
            errorEl.style.display = 'block';
            return;
        }
        if (!alias) {
            errorEl.textContent = '⚠ Hacker alias is required';
            errorEl.style.display = 'block';
            return;
        }

        // Show loading state
        errorEl.style.display = 'none';
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
            <span class="btn-spinner"></span>
            Initializing secure connection...
        `;

        try {
            const result = await GameDB.register(employeeId, displayName, alias);

            if (result.isExisting) {
                // Player has previous data — offer resume or fresh start
                this.playerData = result.data;
                this.showResumeDialog(result.data);
            } else {
                // New player
                this.playerData = result.data;
                this.enterGame();
            }
        } catch (error) {
            console.error('[Registration] Failed:', error);
            errorEl.textContent = '⚠ Registration failed. Please try again.';
            errorEl.style.display = 'block';
            submitBtn.disabled = false;
            submitBtn.innerHTML = `
                Enter the Operation
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                    <polyline points="12 5 19 12 12 19"></polyline>
                </svg>
            `;
        }
    },

    showResumeDialog(data) {
        const completed = Object.values(data.progress).filter(p => p.completed).length;
        const overlay = document.getElementById('registration-overlay');

        document.getElementById('reg-form-section').style.display = 'none';
        document.getElementById('reg-resume-section').style.display = 'block';

        document.getElementById('resume-player-name').textContent = data.alias || data.displayName;
        document.getElementById('resume-score').textContent = data.totalScore.toLocaleString();
        document.getElementById('resume-completed').textContent = `${completed}/6`;
    },

    resumeGame() {
        this.enterGame();
    },

    freshStart() {
        // Reset the player data
        this.playerData.progress = {
            'log-analysis': { completed: false, score: 0, attempts: 0, completedAt: null },
            'phishing': { completed: false, score: 0, attempts: 0, completedAt: null },
            'incident-response': { completed: false, score: 0, attempts: 0, completedAt: null },
            'network-analysis': { completed: false, score: 0, attempts: 0, completedAt: null },
            'threat-hunting': { completed: false, score: 0, attempts: 0, completedAt: null },
            'threat-stacking': { completed: false, score: 0, attempts: 0, completedAt: null },
            'mystery-challenge': { completed: false, score: 0, attempts: 0, completedAt: null },
            'quickfire': { completed: false, score: 0, attempts: 0, completedAt: null }
        };
        this.playerData.totalScore = 0;
        this.playerData.achievements = [];
        this.playerData.timeSpent = 0;
        this.playerData.competitionStartTime = null;

        GameDB.savePlayer(this.playerData);
        this.enterGame();
    },

    enterGame() {
        // Hide registration overlay
        document.getElementById('registration-overlay').classList.remove('active');

        // Set competition start time if not already set
        if (!this.playerData.competitionStartTime) {
            this.playerData.competitionStartTime = Date.now();
            GameDB.savePlayer(this.playerData);
        }

        this.isGameActive = true;

        // Pass player data to the main app
        window.startGameWithPlayer(this.playerData);

        // Start competition timer
        this.startCompetitionTimer();

        // Start leaderboard polling
        this.startLeaderboardPolling();
    },

    // ============================================
    // Competition Timer
    // ============================================
    startCompetitionTimer() {
        const startTime = this.playerData.competitionStartTime;
        const durationMs = this.COMPETITION_DURATION_MINUTES * 60 * 1000;
        const endTime = startTime + durationMs;

        const timerEl = document.getElementById('competition-timer');
        const timerValueEl = document.getElementById('competition-timer-value');

        if (timerEl) timerEl.style.display = 'flex';

        const updateTimer = () => {
            const now = Date.now();
            const remaining = Math.max(0, endTime - now);
            const totalSeconds = Math.floor(remaining / 1000);
            const minutes = Math.floor(totalSeconds / 60);
            const seconds = totalSeconds % 60;

            if (timerValueEl) {
                timerValueEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }

            // 5-minute warning
            if (remaining <= 300000 && remaining > 0) {
                timerEl.classList.add('warning');
            }

            // 1-minute warning
            if (remaining <= 60000 && remaining > 0) {
                timerEl.classList.add('critical');
            }

            // Mystery Challenge unlock at 20 min remaining
            if (remaining <= 20 * 60 * 1000 && remaining > 0) {
                this.unlockMysteryChallenge();
            }

            // Time's up
            if (remaining <= 0) {
                this.endCompetition();
            }
        };

        updateTimer(); // Initial update
        this.timerInterval = setInterval(updateTimer, 1000);
    },

    unlockMysteryChallenge() {
        if (this.mysteryUnlocked) return;
        this.mysteryUnlocked = true;
        
        const card = document.getElementById('mystery-challenge-card');
        if (card) {
            card.style.display = 'flex'; // Use flex or block depending on simulation-card default (which flexes content usually)
        }
    },

    endCompetition() {
        clearInterval(this.timerInterval);
        clearInterval(this.leaderboardInterval);
        this.isGameActive = false;

        // Save final state
        GameDB.savePlayer(this.playerData);

        // Show time's up overlay
        const overlay = document.getElementById('times-up-overlay');
        if (overlay) {
            document.getElementById('final-score-value').textContent = this.playerData.totalScore.toLocaleString();
            const completed = Object.values(this.playerData.progress).filter(p => p.completed).length;
            document.getElementById('final-completed-value').textContent = `${completed}/8`;
            document.getElementById('final-alias-value').textContent = this.playerData.alias || this.playerData.displayName;
            overlay.classList.add('active');
        }
    },

    // ============================================
    // In-Game Mini Leaderboard
    // ============================================
    startLeaderboardPolling() {
        this.updateMiniLeaderboard(); // Initial fetch
        this.leaderboardInterval = setInterval(() => {
            this.updateMiniLeaderboard();
        }, 15000); // Every 15 seconds
    },

    async updateMiniLeaderboard() {
        try {
            const players = await GameDB.getAllPlayers();
            this.renderMiniLeaderboard(players);
        } catch (error) {
            console.error('[Leaderboard] Update failed:', error);
        }
    },

    renderMiniLeaderboard(players) {
        const container = document.getElementById('mini-leaderboard-list');
        if (!container) return;

        const currentId = this.playerData?.employeeId;
        const myRank = players.findIndex(p => p.employeeId === currentId) + 1;
        const top5 = players.slice(0, 5);

        // Update player count
        const countEl = document.getElementById('mini-lb-player-count');
        if (countEl) countEl.textContent = `${players.length} analysts`;

        // Update my rank
        const rankEl = document.getElementById('mini-lb-my-rank');
        if (rankEl) rankEl.textContent = myRank > 0 ? `#${myRank}` : '--';

        container.innerHTML = top5.map((player, idx) => {
            const isMe = player.employeeId === currentId;
            const rankIcons = ['🥇', '🥈', '🥉'];
            const rankDisplay = idx < 3 ? rankIcons[idx] : `#${idx + 1}`;
            const completed = Object.values(player.progress || {}).filter(p => p.completed).length;

            return `
                <div class="mini-lb-row ${isMe ? 'is-me' : ''}">
                    <span class="mini-lb-rank">${rankDisplay}</span>
                    <span class="mini-lb-alias">${player.alias || player.displayName || 'Anonymous'}</span>
                    <span class="mini-lb-score">${player.totalScore.toLocaleString()}</span>
                </div>
            `;
        }).join('');

        // If current player is not in top 5, show them at the bottom
        if (myRank > 5 && currentId) {
            const me = players.find(p => p.employeeId === currentId);
            if (me) {
                container.innerHTML += `
                    <div class="mini-lb-divider">···</div>
                    <div class="mini-lb-row is-me">
                        <span class="mini-lb-rank">#${myRank}</span>
                        <span class="mini-lb-alias">${me.alias || me.displayName}</span>
                        <span class="mini-lb-score">${me.totalScore.toLocaleString()}</span>
                    </div>
                `;
            }
        }
    },

    toggleMiniLeaderboard() {
        const panel = document.getElementById('mini-leaderboard');
        if (panel) {
            panel.classList.toggle('collapsed');
        }
    }
};

// Export for global access
window.CompetitionManager = CompetitionManager;
