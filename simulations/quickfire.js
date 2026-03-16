/**
 * Quick-Fire Bonus Round
 * 15 multiple-choice questions in 90 seconds (6s per question)
 * Max Score: 200 pts
 */

const QuickFireSimulation = {
    questions: [
        {
            q: "Which port is used for RDP by default?",
            options: ["3389", "22", "443", "445"],
            answer: 0
        },
        {
            q: "What does SIEM stand for?",
            options: ["Security Information and Event Management", "System Incident Response Management", "Security Incident and Enterprise Monitoring", "System Information Endpoint Management"],
            answer: 0
        },
        {
            q: "Which technique is Mitre ATT&CK T1566?",
            options: ["Brute Force", "Phishing", "Valid Accounts", "OS Credential Dumping"],
            answer: 1
        },
        {
            q: "What is the primary function of an EDR?",
            options: ["Network traffic filtering", "Endpoint Detection and Response", "Email spam filtering", "External vulnerability scanning"],
            answer: 1
        },
        {
            q: "Which of the following is a network layer protocol?",
            options: ["HTTP", "IP", "TCP", "SMTP"],
            answer: 1
        },
        {
            q: "What does a 403 HTTP status code mean?",
            options: ["Not Found", "Internal Server Error", "Forbidden", "Unauthorized"],
            answer: 2
        },
        {
            q: "Which hash algorithm is considered cryptographically broken?",
            options: ["SHA-256", "MD5", "SHA-3", "bcrypt"],
            answer: 1
        },
        {
            q: "In Windows, where are password hashes stored?",
            options: ["/etc/shadow", "C:\\Windows\\System32\\config\\SAM", "registry.dat", "/var/log/auth.log"],
            answer: 1
        },
        {
            q: "What type of attack involves manipulating a DNS cache?",
            options: ["DNS Tunneling", "DNS Spoofing", "DNS Zone Transfer", "Domain Fronting"],
            answer: 1
        },
        {
            q: "Which protocol is used to securely transfer files over SSH?",
            options: ["FTP", "TFTP", "SFTP", "FTPS"],
            answer: 2
        },
        {
            q: "What does 'Lateral Movement' refer to in a breach?",
            options: ["Exfiltrating data out of the network", "Moving from one compromised system to another", "Escalating privileges on a single system", "Deleting logs to hide traces"],
            answer: 1
        },
        {
            q: "Which of these is a common living-off-the-land (LotL) binary?",
            options: ["nmap.exe", "powershell.exe", "metasploit framework", "wireshark.exe"],
            answer: 1
        },
        {
            q: "What is Cross-Site Scripting (XSS)?",
            options: ["Injecting malicious SQL statements", "Injecting malicious client-side scripts", "Intercepting network traffic", "Guessing passwords rapidly"],
            answer: 1
        },
        {
            q: "Which port is typically used by SMB?",
            options: ["21", "25", "3389", "445"],
            answer: 3
        },
        {
            q: "What is the objective of ransomware?",
            options: ["Steal processing power", "Display unclosable ads", "Encrypt files and demand payment", "Log keystrokes silently"],
            answer: 2
        }
    ],

    currentQuestionIndex: 0,
    score: 0,
    answers: [],
    questionTimer: null,
    timePerQuestion: 6,
    timeRemaining: 6,
    isActive: false,

    render() {
        this.currentQuestionIndex = 0;
        this.score = 0;
        this.answers = [];
        this.timeRemaining = this.timePerQuestion;
        this.isActive = true;

        return `
            <div class="quickfire-sim">
                <div class="quickfire-header">
                    <div class="quickfire-title">
                        <span class="lightning-icon">⚡</span> QUICK-FIRE ROUND
                    </div>
                    <div class="quickfire-stats">
                        <span class="qf-stat">Q: <span id="qf-current">1</span>/${this.questions.length}</span>
                        <span class="qf-stat timer" id="qf-timer">${this.timeRemaining}s</span>
                    </div>
                </div>

                <div class="qf-progress-bar">
                    <div class="qf-progress-fill" id="qf-progress-fill"></div>
                </div>

                <div class="qf-question-container" id="qf-question-container">
                    <!-- Populated by JS -->
                </div>
            </div>
        `;
    },

    init() {
        this.showQuestion(0);
    },

    showQuestion(index) {
        if (index >= this.questions.length) {
            this.finishSimulation();
            return;
        }

        this.currentQuestionIndex = index;
        this.timeRemaining = this.timePerQuestion;
        
        const q = this.questions[index];
        const container = document.getElementById('qf-question-container');
        document.getElementById('qf-current').textContent = index + 1;

        // Randomize option order slightly for visual variety
        const optionIndices = [0, 1, 2, 3];
        // We'll keep them static for now to avoid confusing UI shifts, 
        // but typically you'd shuffle these. For simplicity, just display them.

        container.innerHTML = `
            <h2 class="qf-question-text" style="animation: qfSlideIn 0.3s ease">${q.q}</h2>
            <div class="qf-options" id="qf-options">
                ${q.options.map((opt, i) => `
                    <button class="qf-option-btn" onclick="QuickFireSimulation.selectAnswer(${i})">
                        <span class="qf-opt-letter">${String.fromCharCode(65 + i)}</span>
                        <span class="qf-opt-text">${opt}</span>
                    </button>
                `).join('')}
            </div>
        `;

        this.startQuestionTimer();
    },

    startQuestionTimer() {
        clearInterval(this.questionTimer);
        const timerEl = document.getElementById('qf-timer');
        const fillEl = document.getElementById('qf-progress-fill');
        
        timerEl.textContent = `${this.timeRemaining}s`;
        fillEl.style.transition = 'none';
        fillEl.style.width = '100%';

        requestAnimationFrame(() => {
            fillEl.style.transition = `width ${this.timePerQuestion}s linear`;
            fillEl.style.width = '0%';
        });

        this.questionTimer = setInterval(() => {
            if (!this.isActive) {
                clearInterval(this.questionTimer);
                return;
            }
            
            this.timeRemaining--;
            timerEl.textContent = `${this.timeRemaining}s`;

            if (this.timeRemaining <= 3) {
                timerEl.classList.add('critical');
            } else {
                timerEl.classList.remove('critical');
            }

            if (this.timeRemaining <= 0) {
                this.selectAnswer(-1); // Time up = wrong
            }
        }, 1000);
    },

    selectAnswer(selectedIndex) {
        if (!this.isActive) return;
        
        clearInterval(this.questionTimer);
        const q = this.questions[this.currentQuestionIndex];
        const isCorrect = selectedIndex === q.answer;
        
        if (isCorrect) {
            this.score++;
        }

        this.answers.push({
            q: q.q,
            playerOpt: selectedIndex >= 0 ? q.options[selectedIndex] : 'Time Up',
            correctOpt: q.options[q.answer],
            isCorrect: isCorrect
        });

        // Show brief visual feedback
        const btns = document.querySelectorAll('.qf-option-btn');
        if (btns.length > 0) {
            btns.forEach((btn, idx) => {
                btn.disabled = true;
                if (idx === q.answer) {
                    btn.classList.add('correct');
                } else if (idx === selectedIndex && !isCorrect) {
                    btn.classList.add('wrong');
                }
            });
        }

        // Wait a tiny bit (300ms) then go to next
        setTimeout(() => {
            if (this.isActive) {
                this.showQuestion(this.currentQuestionIndex + 1);
            }
        }, 400);
    },

    finishSimulation() {
        this.isActive = false;
        clearInterval(this.questionTimer);

        const total = this.questions.length;
        const finalScore = Math.round((this.score / total) * 200);

        const feedback = this.answers.map((a, i) => {
            return `${a.isCorrect ? '✅' : '❌'} Q${i+1}: ${a.q}<br>
                    <span style="color:var(--text-muted);font-size:0.85rem;">
                    Your answer: ${a.playerOpt} | Correct: ${a.correctOpt}
                    </span>`;
        });

        const container = document.getElementById('qf-question-container');
        container.innerHTML = `
            <div class="qf-results">
                <h2>Round Complete!</h2>
                <div class="qf-score-circle">
                    ${this.score} / ${total}
                </div>
                <p>Bonus Points Earned: <strong>${finalScore}</strong></p>
                <div class="qf-actions">
                    <button class="btn btn-primary" onclick="completeSimulation('quickfire', ${finalScore}, 200, ${JSON.stringify(feedback).replace(/"/g, '&quot;')})">
                        Submit Score
                    </button>
                </div>
            </div>
        `;
        document.querySelector('.qf-progress-bar').style.display = 'none';
    }
};

window.QuickFireSimulation = QuickFireSimulation;
