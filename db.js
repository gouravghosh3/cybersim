/**
 * GameDB - Dual-mode Database Abstraction Layer
 * Automatically detects SharePoint vs local environment
 * 
 * SharePoint mode: Uses SharePoint REST API with list "CyberSimScores"
 * Local mode: Uses localStorage with key "cybersim-players"
 */

const GameDB = {
    mode: 'local', // 'local' or 'sharepoint'
    listName: 'CyberSimScores',
    siteUrl: '',
    digest: null,
    digestExpiry: 0,
    currentPlayerItemId: null, // SharePoint list item ID for MERGE updates
    currentEmployeeId: null,

    // ============================================
    // Initialization
    // ============================================
    init() {
        if (this.isSharePoint()) {
            this.mode = 'sharepoint';
            // Extract site URL from current page
            // e.g. https://sites.jpmchase.net/sites/YourSite
            const path = window.location.pathname;
            const siteMatch = path.match(/^(\/sites\/[^/]+)/);
            this.siteUrl = siteMatch ? window.location.origin + siteMatch[1] : window.location.origin;
            console.log('[GameDB] SharePoint mode detected. Site URL:', this.siteUrl);
        } else {
            this.mode = 'local';
            console.log('[GameDB] Local mode - using localStorage');
        }
    },

    isSharePoint() {
        return window.location.hostname === 'sites.jpmchase.net';
    },

    // ============================================
    // SharePoint REST API Helpers
    // ============================================
    async getRequestDigest() {
        // Return cached digest if still valid (refresh 5 min before expiry)
        if (this.digest && Date.now() < this.digestExpiry - 300000) {
            return this.digest;
        }

        try {
            const response = await fetch(`${this.siteUrl}/_api/contextinfo`, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json;odata=verbose',
                    'Content-Type': 'application/json;odata=verbose'
                },
                credentials: 'include'
            });

            if (!response.ok) throw new Error(`Digest request failed: ${response.status}`);

            const data = await response.json();
            this.digest = data.d.GetContextWebInformation.FormDigestValue;
            const timeout = data.d.GetContextWebInformation.FormDigestTimeoutSeconds;
            this.digestExpiry = Date.now() + (timeout * 1000);

            console.log('[GameDB] Request digest refreshed, expires in', timeout, 'seconds');
            return this.digest;
        } catch (error) {
            console.error('[GameDB] Failed to get request digest:', error);
            throw error;
        }
    },

    getApiUrl(query) {
        return `${this.siteUrl}/_api/web/lists/getbytitle('${this.listName}')/items${query || ''}`;
    },

    async spGet(query) {
        const url = this.getApiUrl(query);
        const response = await fetch(url, {
            headers: {
                'Accept': 'application/json;odata=verbose'
            },
            credentials: 'include'
        });
        if (!response.ok) throw new Error(`SP GET failed: ${response.status}`);
        return response.json();
    },

    async spPost(data) {
        const digest = await this.getRequestDigest();
        const url = this.getApiUrl();
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Accept': 'application/json;odata=verbose',
                'Content-Type': 'application/json;odata=verbose',
                'X-RequestDigest': digest
            },
            credentials: 'include',
            body: JSON.stringify({
                '__metadata': { 'type': `SP.Data.${this.listName}ListItem` },
                'Title': data.Title,
                'GameData': data.GameData
            })
        });
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`SP POST failed: ${response.status} - ${errText}`);
        }
        return response.json();
    },

    async spMerge(itemId, data) {
        const digest = await this.getRequestDigest();
        const url = this.getApiUrl(`(${itemId})`);
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Accept': 'application/json;odata=verbose',
                'Content-Type': 'application/json;odata=verbose',
                'X-RequestDigest': digest,
                'IF-MATCH': '*',
                'X-HTTP-Method': 'MERGE'
            },
            credentials: 'include',
            body: JSON.stringify({
                '__metadata': { 'type': `SP.Data.${this.listName}ListItem` },
                'GameData': data.GameData
            })
        });
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`SP MERGE failed: ${response.status} - ${errText}`);
        }
        // MERGE returns 204 No Content on success
        return true;
    },

    // ============================================
    // Unified API
    // ============================================

    /**
     * Register a new player or return existing record
     * @returns {Object} Player data object
     */
    async register(employeeId, displayName, alias) {
        this.currentEmployeeId = employeeId;

        const newPlayerData = {
            employeeId: employeeId,
            displayName: displayName,
            alias: alias,
            progress: {
                'log-analysis': { completed: false, score: 0, attempts: 0, completedAt: null },
                'phishing': { completed: false, score: 0, attempts: 0, completedAt: null },
                'incident-response': { completed: false, score: 0, attempts: 0, completedAt: null },
                'network-analysis': { completed: false, score: 0, attempts: 0, completedAt: null },
                'threat-hunting': { completed: false, score: 0, attempts: 0, completedAt: null },
                'threat-stacking': { completed: false, score: 0, attempts: 0, completedAt: null }
            },
            totalScore: 0,
            timeSpent: 0,
            achievements: [],
            competitionStartTime: null,
            registeredAt: new Date().toISOString(),
            lastUpdated: new Date().toISOString()
        };

        if (this.mode === 'sharepoint') {
            return this._spRegister(employeeId, newPlayerData);
        } else {
            return this._localRegister(employeeId, newPlayerData);
        }
    },

    /**
     * Load player data by employee ID
     * @returns {Object|null} Player data or null if not found
     */
    async loadPlayer(employeeId) {
        this.currentEmployeeId = employeeId;

        if (this.mode === 'sharepoint') {
            return this._spLoadPlayer(employeeId);
        } else {
            return this._localLoadPlayer(employeeId);
        }
    },

    /**
     * Save/update player data
     * @param {Object} playerData - Full player data object
     */
    async savePlayer(playerData) {
        playerData.lastUpdated = new Date().toISOString();

        if (this.mode === 'sharepoint') {
            return this._spSavePlayer(playerData);
        } else {
            return this._localSavePlayer(playerData);
        }
    },

    /**
     * Get all players (for leaderboard)
     * @returns {Array} Array of player data objects, sorted by totalScore desc
     */
    async getAllPlayers() {
        if (this.mode === 'sharepoint') {
            return this._spGetAllPlayers();
        } else {
            return this._localGetAllPlayers();
        }
    },

    // ============================================
    // Local (localStorage) Implementation
    // ============================================
    _getLocalStore() {
        const raw = localStorage.getItem('cybersim-players');
        return raw ? JSON.parse(raw) : {};
    },

    _setLocalStore(store) {
        localStorage.setItem('cybersim-players', JSON.stringify(store));
    },

    _localRegister(employeeId, newPlayerData) {
        const store = this._getLocalStore();
        if (store[employeeId]) {
            console.log('[GameDB] Local: Existing player found:', employeeId);
            return { isExisting: true, data: store[employeeId] };
        }
        store[employeeId] = newPlayerData;
        this._setLocalStore(store);
        console.log('[GameDB] Local: New player registered:', employeeId);
        return { isExisting: false, data: newPlayerData };
    },

    _localLoadPlayer(employeeId) {
        const store = this._getLocalStore();
        return store[employeeId] || null;
    },

    _localSavePlayer(playerData) {
        const store = this._getLocalStore();
        store[playerData.employeeId] = playerData;
        this._setLocalStore(store);
        // Also keep legacy localStorage for backward compatibility
        localStorage.setItem('cybersim-progress', JSON.stringify({
            progress: playerData.progress,
            totalScore: playerData.totalScore,
            timeSpent: playerData.timeSpent,
            achievements: playerData.achievements
        }));
        return true;
    },

    _localGetAllPlayers() {
        const store = this._getLocalStore();
        return Object.values(store).sort((a, b) => b.totalScore - a.totalScore);
    },

    // ============================================
    // SharePoint Implementation
    // ============================================
    async _spRegister(employeeId, newPlayerData) {
        try {
            // Check if player exists
            const existing = await this._spLoadPlayer(employeeId);
            if (existing) {
                console.log('[GameDB] SP: Existing player found:', employeeId);
                return { isExisting: true, data: existing };
            }

            // Create new item
            const result = await this.spPost({
                Title: employeeId,
                GameData: JSON.stringify(newPlayerData)
            });

            this.currentPlayerItemId = result.d.Id;
            console.log('[GameDB] SP: New player registered:', employeeId, 'ItemId:', this.currentPlayerItemId);
            return { isExisting: false, data: newPlayerData };
        } catch (error) {
            console.error('[GameDB] SP register failed, falling back to local:', error);
            return this._localRegister(employeeId, newPlayerData);
        }
    },

    async _spLoadPlayer(employeeId) {
        try {
            const result = await this.spGet(`?$filter=Title eq '${employeeId}'&$select=Id,Title,GameData`);
            if (result.d.results.length > 0) {
                const item = result.d.results[0];
                this.currentPlayerItemId = item.Id;
                return JSON.parse(item.GameData);
            }
            return null;
        } catch (error) {
            console.error('[GameDB] SP loadPlayer failed, falling back to local:', error);
            return this._localLoadPlayer(employeeId);
        }
    },

    async _spSavePlayer(playerData) {
        try {
            if (!this.currentPlayerItemId) {
                // Try to find the item first
                const result = await this.spGet(`?$filter=Title eq '${playerData.employeeId}'&$select=Id`);
                if (result.d.results.length > 0) {
                    this.currentPlayerItemId = result.d.results[0].Id;
                } else {
                    // Item doesn't exist, create it
                    const createResult = await this.spPost({
                        Title: playerData.employeeId,
                        GameData: JSON.stringify(playerData)
                    });
                    this.currentPlayerItemId = createResult.d.Id;
                    return true;
                }
            }

            await this.spMerge(this.currentPlayerItemId, {
                GameData: JSON.stringify(playerData)
            });
            console.log('[GameDB] SP: Player data saved for:', playerData.employeeId);
            return true;
        } catch (error) {
            console.error('[GameDB] SP savePlayer failed, saving to local:', error);
            this._localSavePlayer(playerData);
            return false;
        }
    },

    async _spGetAllPlayers() {
        try {
            const result = await this.spGet('?$select=Title,GameData&$top=100');
            const players = result.d.results
                .map(item => {
                    try {
                        return JSON.parse(item.GameData);
                    } catch (e) {
                        return null;
                    }
                })
                .filter(p => p !== null)
                .sort((a, b) => b.totalScore - a.totalScore);
            return players;
        } catch (error) {
            console.error('[GameDB] SP getAllPlayers failed, falling back to local:', error);
            return this._localGetAllPlayers();
        }
    },

    // ============================================
    // Utility
    // ============================================

    /**
     * Get the current user's email/login from SharePoint context
     * @returns {string|null}
     */
    getCurrentUser() {
        if (this.mode === 'sharepoint') {
            // _spPageContextInfo is available on SharePoint pages
            if (typeof _spPageContextInfo !== 'undefined') {
                return _spPageContextInfo.userLoginName || _spPageContextInfo.userEmail || null;
            }
        }
        return null;
    },

    /**
     * Clear all local data (for testing)
     */
    clearLocal() {
        localStorage.removeItem('cybersim-players');
        localStorage.removeItem('cybersim-progress');
        console.log('[GameDB] Local data cleared');
    }
};

// Export for global access
window.GameDB = GameDB;
