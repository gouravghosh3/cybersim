# Operation: CyberShield — SOC Analyst Competition Platform

## Overview

**Operation: CyberShield** is a browser-based, competitive cybersecurity training platform for JP Morgan SOC Analyst lab sessions. Up to 50 players register, compete through hands-on simulations within a 60-minute countdown, and scores are ranked on a live projector leaderboard. Top 3 are rewarded, top 10 recognized.

- **URL title:** `Operation: CyberShield | SOC Analyst Competition`
- **No build system / framework** — purely a static site served from `index.html`.
- **Dual-mode database** — localStorage for local testing, SharePoint REST API when hosted on `sites.jpmchase.net`.

---

## Tech Stack

| Layer        | Technology                                  |
|-------------|---------------------------------------------|
| Structure    | HTML5 (`index.html` + `leaderboard.html`)  |
| Styling      | Vanilla CSS (`styles.css`, ~1960 lines)    |
| Logic        | Vanilla JavaScript (ES6+, no modules/bundler) |
| Fonts        | Google Fonts — **Orbitron** (display), **Inter** (body) |
| Database     | Dual-mode: `localStorage` (local) / SharePoint REST API (production) |
| Hosting      | SharePoint Site Assets (production) or any static server (local) |

---

## Directory Structure

```
Simulation/
├── index.html                  # Single-page app shell — game UI
├── leaderboard.html            # Standalone projector leaderboard page
├── app.js                      # Core application logic
├── db.js                       # Dual-mode database abstraction layer
├── registration.js             # Competition flow: registration, timer, mini leaderboard
├── styles.css                  # Full CSS theme & component styles (~1960 lines)
├── context.md                  # ← This file
└── simulations/
    ├── log-analysis.js         # Log Analysis simulation
    ├── splunk-query.js         # Splunk SPL query practice
    ├── phishing-detection.js   # Phishing email identification
    ├── incident-response.js    # Ransomware incident response
    ├── network-analysis.js     # Packet capture analysis
    ├── threat-hunting.js       # Threat hunting via clustering
    ├── threat-stacking.js      # Threat hunting via stacking
    ├── mystery-challenge.js    # Live breach response (auto-unlocks)
    └── quickfire.js            # Rapid-fire trivia bonus round
```

---

## Architecture

### Design Pattern
The app follows a **Single-Page Application (SPA)** pattern without a framework. Views are toggled via CSS class manipulation (`view.active`). Each simulation module is a **global singleton object** attached to `window`, exposing `render()`, `init()`, and domain-specific methods.

### Application Flow
```
index.html loads → scripts loaded (db.js → simulations → registration.js → app.js)
                 → DOMContentLoaded fires
                 → GameDB.init() — detects environment (SharePoint or local)
                 → CompetitionManager.showRegistration() — shows registration overlay
                 → Player registers or resumes
                 → startGameWithPlayer(playerData) — merges data into AppState
                 → initNavigation() → updateUI() → initProgressView() → startTimeTracking()
                 → CompetitionManager.startCompetitionTimer() — 60-min countdown
                 → CompetitionManager.startLeaderboardPolling() — mini leaderboard every 15s
```

### View System
Four views, switched by `showView(viewName)`:
| View          | Element ID            | Description                        |
|--------------|------------------------|------------------------------------|
| Dashboard     | `dashboard-view`      | Welcome banner, quick stats        |
| Simulations   | `simulations-view`    | 8 simulation cards (grid layout)   |
| Progress      | `progress-view`       | Ring chart, radar chart, achievements |
| Simulation    | `simulation-view`     | Active simulation content (dynamic) |

### Overlay System
| Overlay              | ID                    | Trigger                            |
|---------------------|-----------------------|------------------------------------|
| Registration         | `registration-overlay`| On page load (before game starts)  |
| Time's Up            | `times-up-overlay`    | 60-min timer ends; offers Proficiency Card download |
| Results Modal        | `modal-overlay`       | After simulation; includes MITRE Intel Debrief |
| Takeaway Card        | `takeaway-overlay`    | Clicking "View Proficiency Card"   |

---

## Database Layer: `db.js`

### `GameDB` Singleton
Auto-detects the environment and routes all data operations:
- **SharePoint mode:** when `window.location.hostname === 'sites.jpmchase.net'`
- **Local mode:** all other hostnames (uses `localStorage` key `cybersim-players`)

### Unified API
| Method                           | Description                                |
|----------------------------------|--------------------------------------------|
| `GameDB.init()`                  | Detect environment, set mode               |
| `GameDB.isSharePoint()`          | Returns true if on SharePoint              |
| `GameDB.register(id, name, alias)` | Create or find existing player            |
| `GameDB.loadPlayer(id)`          | Fetch player data by employee ID           |
| `GameDB.savePlayer(data)`        | Upsert player data                         |
| `GameDB.getAllPlayers()`          | Get all players sorted by score (for leaderboard) |
| `GameDB.getCurrentUser()`        | Get employee ID from `_spPageContextInfo`  |

### SharePoint Details
- **List name:** `CyberSimScores`
- **Columns:** `Title` (employee ID), `GameData` (JSON string)
- **Endpoints:** `/_api/web/lists/getbytitle('CyberSimScores')/items`
- **Auth:** Uses session cookie + `X-RequestDigest` (auto-refreshed)
- **Fallback:** If any SP API call fails, falls back to localStorage silently

### localStorage Structure
```js
// Key: 'cybersim-players'
{
  "EMP-001": {
    employeeId: "EMP-001",
    displayName: "Jane Doe",
    alias: "CyberPhantom",
    progress: { ... },
    totalScore: 1200,
    timeSpent: 35,
    achievements: ["first-blood", "phish-finder"],
    competitionStartTime: 1742158800000,
    registeredAt: "2026-03-17T02:00:00Z",
    lastUpdated: "2026-03-17T02:35:00Z"
  },
  "EMP-002": { ... }
}
```

---

## Competition Flow: `registration.js`

### `CompetitionManager` Singleton
Manages the full competition lifecycle:

| Method / Property                | Description                                   |
|----------------------------------|-----------------------------------------------|
| `showRegistration()`             | Show registration overlay; auto-detect ID on SharePoint |
| `handleRegistration()`           | Validate form, register via GameDB            |
| `showResumeDialog(data)`         | Offer resume or fresh start for returning players |
| `enterGame()`                    | Hide overlay, set start time, begin timer     |
| `startCompetitionTimer()`        | 60-min countdown; warnings at 5min and 1min   |
| `endCompetition()`               | Freeze game, show time's-up overlay           |
| `startLeaderboardPolling()`      | Poll `getAllPlayers()` every 15s              |
| `renderMiniLeaderboard(players)` | Update bottom-right floating panel            |
| `COMPETITION_DURATION_MINUTES`   | Default: `60`                                 |

### Timer States
| Remaining    | CSS Class  | Visual Effect                          |
|-------------|------------|----------------------------------------|
| > 5 minutes  | (default)  | Cyan text, steady                      |
| ≤ 5 minutes  | `warning`  | Yellow text, 1s pulse animation        |
| ≤ 1 minute   | `critical` | Red text, 0.5s pulse animation         |
| 0            | —          | Game freezes, time's-up overlay shown  |

---

## Core File: `app.js`

### State Management — `AppState`
```js
AppState = {
    currentView: 'dashboard',
    currentSimulation: null,
    progress: {
        'log-analysis':     { completed, score, attempts, completedAt },
        'phishing':         { completed, score, attempts, completedAt },
        'incident-response':{ completed, score, attempts, completedAt },
        'network-analysis': { completed, score, attempts, completedAt },
        'threat-hunting':   { completed, score, attempts, completedAt },
        'threat-stacking':  { completed, score, attempts, completedAt },
        'mystery-challenge':{ completed, score, attempts, completedAt },
        'quickfire':        { completed, score, attempts, completedAt }
    },
    totalScore: 0,
    timeSpent: 0,        // minutes
    startTime: null,
    simulationStartTime: null,
    consecutiveHighScores: 0,
    achievements: [],
    // Competition fields
    employeeId: null,
    displayName: null,
    alias: null,
    competitionStartTime: null
}
```
- Persisted via `GameDB.savePlayer()` (async, fire-and-forget for UI responsiveness).
- `saveProgress()` syncs AppState → GameDB and updates CompetitionManager's reference.

### Key Functions
| Function                 | Purpose                                            |
|-------------------------|----------------------------------------------------|
| `startGameWithPlayer(data)` | Called by CompetitionManager after registration  |
| `showView(name)`         | Switch between Dashboard / Simulations / Progress  |
| `startSimulation(id)`    | Load simulation into `#simulation-container`; set `simulationStartTime` |
| `completeSimulation()`   | Calculates speed + streak bonuses, saves to server, shows results |
| `checkAchievements()`    | Award badges based on completion/scores            |
| `exitSimulation()`       | Return to simulations view                         |
| `showResultsModal()`     | Display scores, bonuses, feedback, and MITRE Debrief |
| `resetProgress()`        | Clear localStorage and reset all state             |

### Competition-Awareness
- `completeSimulation()` checks `CompetitionManager.isGameActive` — if the timer has expired, it redirects to the simulations view instead of processing the result.

### Ranking System
| Score Threshold | Rank           |
|----------------|----------------|
| 0              | Novice         |
| 500            | Analyst I      |
| 1000           | Analyst II     |
| 1500           | Senior Analyst |
| 2000           | Expert         |
| 2500           | Master         |

### Achievements
| ID             | Name            | Trigger                                |
|----------------|-----------------|----------------------------------------|
| first-blood    | First Blood     | Complete any simulation                |
| log-master     | Log Master      | 100% on Log Analysis                  |
| phish-finder   | Phish Finder    | Identify all phishing emails           |
| responder      | First Responder | Complete Incident Response             |
| network-ninja  | Network Ninja   | Perfect Network Analysis               |
| completionist  | Completionist   | Complete all 6 simulations             |
| perfectionist  | Perfectionist   | 100% on all simulations                |
| dedicated      | Dedicated       | Spend 1 hour training                  |

---

## Simulation Modules

### Global API Contract
Each simulation module exports a global singleton object with:
- `render()` → Returns HTML string for the simulation UI
- `init()` → Called after render; sets up timers/events
- Calls `completeSimulation(id, score, maxScore, feedback[])` when done
- Calls `exitSimulation()` to abort

### Competition Fairness
All randomization has been removed:
- **Log Analysis & Network Analysis** — always use scenario index `0` (no random selection)
- **Phishing Detection** — emails presented in fixed order (no shuffle)
- All players face the exact same challenges in the same order.

### 1. Log Analysis (`log-analysis.js`)
- **Object:** `LogAnalysisSimulation`
- **Max Score:** 500
- **Scenario:** Brute Force Attack Detection (fixed)
- **Gameplay:** Click to flag malicious log entries, then submit analysis
- **Scoring:** `(correctHits / total) × 500 - (falsePositives × 50) - (missed × 25)`

### 2. Splunk Query (`splunk-query.js`)
- **Object:** `SplunkQuerySimulation`
- **Max Score:** 600 (6 challenges × 100 pts)
- **Progress Key:** Maps to `log-analysis` in AppState
- **Gameplay:** Write SPL queries against sample SIEM data; validated by keyword matching
- **Challenges:** Find failed logins, count by source IP, identify attack source, firewall blocks, user activity timeline, credential stuffing detection
- **Query Engine:** Simple client-side filter/aggregation simulation

### 3. Phishing Detection (`phishing-detection.js`)
- **Object:** `PhishingSimulation`
- **Max Score:** 300
- **Emails:** 6 emails (3 phishing, 3 legitimate), fixed order
- **Gameplay:** Review each email, mark as SAFE or PHISHING
- **Scoring:** `(correctCount / total) × 300`

### 4. Incident Response (`incident-response.js`)
- **Object:** `IncidentResponseSimulation`
- **Max Score:** 750 (7 steps × ~100 pts optimal)
- **Scenario:** Ransomware Incident Response (multi-step decision tree)
- **Steps:** Detection → Containment → Evidence Preservation → Investigation → Eradication → Recovery → Post-Incident
- **Gameplay:** Choose from 4 options per step; each has a point value and feedback

### 5. Network Traffic Analysis (`network-analysis.js`)
- **Object:** `NetworkAnalysisSimulation`
- **Max Score:** 600
- **Scenario:** C2 Beacon Detection (fixed)
- **Gameplay:** Flag suspicious packets in a table, then submit
- **Scoring:** `(correctHits / total) × 600 - (falsePositives × 40) - (missed × 30)`

### 6. Threat Hunting: Clustering (`threat-hunting.js`)
- **Object:** `ThreatHuntingSimulation`
- **Max Score:** 800 (4 scenarios × 200 pts)
- **Scenarios:** Suspicious Update Traffic, DNS Query Analysis, Authentication Time Analysis, Process Execution Clustering
- **Gameplay:** Identify "cluster of one" outliers in data tables
- **Scoring:** 200 for perfect; otherwise `(correct × 100) - (FP × 50) - (missed × 50)`

### 7. Threat Hunting: Stacking (`threat-stacking.js`)
- **Object:** `ThreatStackingSimulation`
- **Max Score:** 800 (4 scenarios × 200 pts)
- **Scenarios:** User Agent Analysis, Parent Process Analysis, Outbound Port Analysis, Downloaded File Extension Analysis
- **Gameplay:** Data sorted by frequency (ascending); flag least-common suspicious items
- **Scoring:** 200 for perfect; otherwise `(correct × 80) - (FP × 40) - (missed × 30)`

### 8. Live Breach Response (`mystery-challenge.js`)
- **Object:** `MysteryChallenge`
- **Max Score:** 400
- **Unlock Condition:** Auto-unlocks when 20 minutes remain on the competition timer.
- **Gameplay:** Rapidly triage 10 incoming SOC alerts within a 15-second strict timer each.
- **Scoring:** Correct (+40), Incorrect (-20), Missed (-10)

### 9. Quick-Fire Bonus Round (`quickfire.js`)
- **Object:** `QuickFireSimulation`
- **Max Score:** 200
- **Gameplay:** Answer 15 rapid-fire multiple-choice questions with a 6-second timer per question.
- **Scoring:** Time-based scaling (up to 20 pts per question).

---

## Leaderboard: `leaderboard.html`

A standalone full-screen page designed for projection on a shared screen:
- **Podium:** Top 3 players with gold/silver/bronze styling
- **Table:** All players ranked by score; top 10 highlighted with cyan border
- **Activity Feed:** Scrolling ticker showing recent completions and joins
- **Polling:** Fetches `GameDB.getAllPlayers()` every 5 seconds
- **Self-contained:** Has its own inline CSS (dark cyberpunk theme), uses `db.js` for data access

---

## Mini Leaderboard Panel

A floating collapsible panel in the bottom-right corner of the game screen:
- Shows top 5 players + current player's rank
- Updates every 15 seconds
- Toggleable via header click
- Highlights current player's row

---

## Styling (`styles.css`)

### Design System
- **Theme:** Dark cyberpunk with glassmorphism effects
- **Color Palette:** Cyan (`#00f5ff`), Purple (`#b24dff`), Green (`#00ff88`), Orange (`#ff6b35`), Red (`#ff3860`), Yellow (`#ffd93d`)
- **Typography:** Orbitron (headings/display), Inter (body text)
- **Animated Elements:** Scan line, blinking cursor, hover glow, fade-in transitions, shield pulse, timer pulse, glitch effect

### Key CSS Variables
```css
--bg-primary:   #0a0a0f
--bg-secondary:  #12121a
--bg-card:       rgba(20, 20, 30, 0.8)
--cyan / --purple / --green / --orange / --red / --yellow
--sidebar-width: 260px
--font-display:  'Orbitron'
--font-body:     'Inter'
```

### Component Styles Covered
Sidebar, nav items, buttons (primary/outline/card), simulation cards, progress bars, terminal window, modal overlay, packet table, email viewer, log entries, incident timeline, **registration overlay**, **competition timer**, **time's-up overlay**, **mini leaderboard panel**, resume dialog, loading spinner.

---

## Data Flow

```
Page Load
  → GameDB.init() detects environment
  → Registration overlay shown
  → Player enters ID + name + alias → GameDB.register()
  → startGameWithPlayer(playerData) merges into AppState
  → Competition timer starts (60 min countdown)
  → Mini leaderboard polling starts (15s interval)

During Gameplay
  → User clicks "Start Simulation"
  → startSimulation(id) loads simulation
  → Simulation.render() → HTML injected → Simulation.init()
  → User interacts, then submits
  → completeSimulation() → checks isGameActive → updates AppState
  → saveProgress() → GameDB.savePlayer() (async)
  → Results modal displayed
  → Mini leaderboard updates on next poll

Timer Expiry
  → endCompetition() → freeze game → time's-up overlay
  → Final save to GameDB

Projector Leaderboard
  → leaderboard.html polls GameDB.getAllPlayers() every 5s
  → Renders podium + ranked table + activity feed
```

---

## Script Load Order

```html
<script src="db.js"></script>           <!-- Database layer (must be first) -->
<script src="simulations/..."></script> <!-- All 7 simulation modules -->
<script src="registration.js"></script> <!-- Competition manager (needs GameDB) -->
<script src="app.js"></script>          <!-- Main app (needs everything above) -->
```

---

## SharePoint Deployment

### Prerequisites
1. Create a SharePoint List named **`CyberSimScores`** on the target site
   - `Title` column (built-in, single line) — used for Employee ID
   - `GameData` column (multi-line plain text) — stores JSON string
2. Upload all files to the site's **Site Assets** library

### Detection Logic
`GameDB.isSharePoint()` checks `window.location.hostname === 'sites.jpmchase.net'`

### API Endpoints Used
```
POST   /_api/contextinfo                                    → Get request digest
GET    /_api/web/lists/getbytitle('CyberSimScores')/items   → Read players
POST   /_api/web/lists/getbytitle('CyberSimScores')/items   → Create player
MERGE  /_api/web/lists/getbytitle('CyberSimScores')/items(id) → Update player
```

---

## Known Quirks & Notes

1. **Splunk Query maps to `log-analysis`** — The Splunk simulation calls `completeSimulation('log-analysis', ...)`, sharing the same progress key as Log Analysis.
2. **Dual-mode database** — All data operations go through `GameDB`; SharePoint failures silently fall back to localStorage.
3. **No module system** — All scripts are globals loaded via `<script>` tags; load order matters (`db.js` first, `app.js` last).
4. **Simulation content is template-literal HTML** — Each module builds its UI via JS string templates, not a component framework.
5. **Timer is per-player** — Each player's `competitionStartTime` is saved in their record, so page refresh doesn't reset the timer.
6. **Request digest expiry** — SharePoint digest tokens expire every ~30 min; `GameDB` auto-refreshes 5 min before expiry.
7. **Answer keys are in source** — `malicious: true`, `isPhishing: true` etc. are still visible in simulation JS files (anti-cheat obfuscation not yet implemented).
