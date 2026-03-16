/**
 * Incident Response Simulation
 * Handle a security incident by choosing correct response actions
 */

const IncidentResponseSimulation = {
    currentStep: 0,
    score: 0,
    maxScore: 750,
    choices: [],

    scenario: {
        title: 'Ransomware Incident Response',
        briefing: `ALERT: Multiple endpoints in the Finance department have reported unusual file encryption activity. Initial reports indicate files are being renamed with a ".encrypted" extension. The IT helpdesk received 5 calls in the last 10 minutes from users who can't access their documents.`,
        steps: [
            {
                id: 1,
                title: 'Initial Detection',
                description: 'You have just received the alert. What is your FIRST action?',
                options: [
                    {
                        id: 'a',
                        text: 'Immediately shut down all Finance department computers',
                        correct: false,
                        points: 25,
                        feedback: 'Premature shutdown can destroy volatile forensic evidence and disrupt legitimate business operations. Assessment should come first.'
                    },
                    {
                        id: 'b',
                        text: 'Assess the scope by checking how many systems are affected',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! Understanding the scope helps prioritize response actions and allocate resources effectively.'
                    },
                    {
                        id: 'c',
                        text: 'Send a company-wide email warning everyone about the ransomware',
                        correct: false,
                        points: 15,
                        feedback: 'Premature communication can cause panic and may tip off attackers if they are monitoring communications.'
                    },
                    {
                        id: 'd',
                        text: 'Start restoring files from backup immediately',
                        correct: false,
                        points: 20,
                        feedback: 'Restoration before containment could result in backed-up files being encrypted too.'
                    }
                ]
            },
            {
                id: 2,
                title: 'Containment',
                description: 'You have identified 12 affected endpoints. The encryption is still spreading. What is your next action?',
                options: [
                    {
                        id: 'a',
                        text: 'Isolate affected network segment from the corporate network',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! Network isolation prevents lateral movement while preserving evidence on affected systems.'
                    },
                    {
                        id: 'b',
                        text: 'Begin formatting and reimaging all affected machines',
                        correct: false,
                        points: 10,
                        feedback: 'This destroys forensic evidence needed to understand the attack and could miss the infection source.'
                    },
                    {
                        id: 'c',
                        text: 'Contact the attackers to negotiate ransom payment',
                        correct: false,
                        points: 0,
                        feedback: 'Payment should never be the first response. It funds criminal activity and doesn\'t guarantee decryption.'
                    },
                    {
                        id: 'd',
                        text: 'Disable all user accounts in Active Directory',
                        correct: false,
                        points: 30,
                        feedback: 'While protective, this is too aggressive and disrupts all business operations unnecessarily.'
                    }
                ]
            },
            {
                id: 3,
                title: 'Evidence Preservation',
                description: 'The affected segment is isolated. What evidence should you prioritize collecting?',
                options: [
                    {
                        id: 'a',
                        text: 'Screenshot the ransom note and delete the infected files',
                        correct: false,
                        points: 20,
                        feedback: 'Deleting infected files destroys critical evidence for forensic analysis and potential decryption.'
                    },
                    {
                        id: 'b',
                        text: 'Memory dumps, network traffic logs, and filesystem images',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! These provide the most valuable forensic evidence for analysis and potential recovery.'
                    },
                    {
                        id: 'c',
                        text: 'Only collect the encrypted files for later analysis',
                        correct: false,
                        points: 35,
                        feedback: 'While useful, this misses crucial memory artifacts and network indicators of compromise.'
                    },
                    {
                        id: 'd',
                        text: 'Interview all affected users immediately',
                        correct: false,
                        points: 25,
                        feedback: 'User interviews are valuable but technical evidence collection should be prioritized first.'
                    }
                ]
            },
            {
                id: 4,
                title: 'Investigation',
                description: 'Analysis reveals the ransomware entered via a phishing email with a malicious Excel macro. What do you check next?',
                options: [
                    {
                        id: 'a',
                        text: 'Check if other employees received the same phishing email',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! Identifying all recipients helps find other potential infections before they activate.'
                    },
                    {
                        id: 'b',
                        text: 'Focus only on the Finance department since they were targeted',
                        correct: false,
                        points: 25,
                        feedback: 'Phishing campaigns often target multiple departments. Limiting scope could miss other infections.'
                    },
                    {
                        id: 'c',
                        text: 'Immediately block all Excel files from being opened company-wide',
                        correct: false,
                        points: 30,
                        feedback: 'Overly aggressive blocking disrupts business. Targeted blocking of the specific malicious file is better.'
                    },
                    {
                        id: 'd',
                        text: 'Report the phishing email to the email provider only',
                        correct: false,
                        points: 15,
                        feedback: 'While useful, internal investigation should be prioritized to prevent further damage.'
                    }
                ]
            },
            {
                id: 5,
                title: 'Eradication',
                description: 'You have identified all 25 affected systems. How do you proceed with eradication?',
                options: [
                    {
                        id: 'a',
                        text: 'Run antivirus scans on affected systems and delete detected malware',
                        correct: false,
                        points: 35,
                        feedback: 'Ransomware may have persistence mechanisms that AV alone won\'t fully remove.'
                    },
                    {
                        id: 'b',
                        text: 'Reimage systems from known-good baseline and restore from clean backups',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! Complete reimaging ensures all malware and persistence mechanisms are eliminated.'
                    },
                    {
                        id: 'c',
                        text: 'Manually delete all files created by the malware',
                        correct: false,
                        points: 20,
                        feedback: 'Manual cleanup is error-prone and likely to miss registry changes and persistence mechanisms.'
                    },
                    {
                        id: 'd',
                        text: 'Use the decryption key found online to restore files in place',
                        correct: false,
                        points: 40,
                        feedback: 'Even with decryption, the system may still contain backdoors. Reimaging is safer.'
                    }
                ]
            },
            {
                id: 6,
                title: 'Recovery',
                description: 'Systems are reimaged. What is the correct order to bring services back online?',
                options: [
                    {
                        id: 'a',
                        text: 'Restore all systems simultaneously to minimize downtime',
                        correct: false,
                        points: 15,
                        feedback: 'Simultaneous restoration risks overwhelming IT staff and makes it hard to detect issues.'
                    },
                    {
                        id: 'b',
                        text: 'Restore critical systems first with enhanced monitoring, then others in phases',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! Phased recovery with monitoring ensures any remaining issues are caught quickly.'
                    },
                    {
                        id: 'c',
                        text: 'Let users decide which systems to restore based on their needs',
                        correct: false,
                        points: 10,
                        feedback: 'Uncoordinated restoration can cause security gaps and inconsistent monitoring.'
                    },
                    {
                        id: 'd',
                        text: 'Only restore systems that had encrypted files',
                        correct: false,
                        points: 30,
                        feedback: 'Other systems may have been compromised without visible encryption.'
                    }
                ]
            },
            {
                id: 7,
                title: 'Post-Incident',
                description: 'The incident is resolved. What is your MOST important post-incident action?',
                options: [
                    {
                        id: 'a',
                        text: 'Send a blame report identifying which user clicked the phishing link',
                        correct: false,
                        points: 0,
                        feedback: 'Blaming users creates a culture of fear and discourages reporting of future incidents.'
                    },
                    {
                        id: 'b',
                        text: 'Document lessons learned and improve detection/prevention controls',
                        correct: true,
                        points: 100,
                        feedback: 'Correct! Post-incident review improves organizational resilience against future attacks.'
                    },
                    {
                        id: 'c',
                        text: 'Close the incident ticket and move on to other priorities',
                        correct: false,
                        points: 10,
                        feedback: 'Skipping post-incident analysis means missing valuable improvement opportunities.'
                    },
                    {
                        id: 'd',
                        text: 'Immediately implement all security tools the vendor recommends',
                        correct: false,
                        points: 25,
                        feedback: 'New tools should be evaluated based on the specific lessons learned, not vendor recommendations.'
                    }
                ]
            }
        ]
    },

    render() {
        this.currentStep = 0;
        this.score = 0;
        this.choices = [];

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">${this.scenario.title}</h2>
                <div class="simulation-timer">
                    Step <span id="step-counter">1</span> of ${this.scenario.steps.length}
                </div>
            </div>
            
            <div class="simulation-instructions">
                <h4>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    Incident Alert
                </h4>
                <p>${this.scenario.briefing}</p>
            </div>
            
            <div class="simulation-content" id="incident-content">
                ${this.renderStep(0)}
            </div>
            
            <div class="simulation-actions">
                <button class="btn btn-outline" onclick="exitSimulation()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="19" y1="12" x2="5" y2="12"/>
                        <polyline points="12 19 5 12 12 5"/>
                    </svg>
                    Exit
                </button>
                <div class="score-display-inline" style="color: var(--cyan); font-family: var(--font-display);">
                    Score: <span id="current-score">0</span>
                </div>
            </div>
        `;
    },

    renderStep(stepIndex) {
        const step = this.scenario.steps[stepIndex];
        const previousChoice = this.choices.find(c => c.stepId === step.id);

        return `
            <div class="incident-timeline">
                ${this.scenario.steps.slice(0, stepIndex + 1).map((s, idx) => {
            const choice = this.choices.find(c => c.stepId === s.id);
            const isCompleted = idx < stepIndex;
            const isActive = idx === stepIndex;

            return `
                        <div class="incident-step ${isCompleted ? 'completed' : ''} ${isActive ? 'active' : ''}">
                            <div class="incident-step-title">Step ${idx + 1}: ${s.title}</div>
                            <div class="incident-step-desc">${s.description}</div>
                            ${isActive && !previousChoice ? `
                                <div class="incident-options">
                                    ${s.options.map(opt => `
                                        <div class="incident-option" data-option="${opt.id}" onclick="IncidentResponseSimulation.selectOption(${s.id}, '${opt.id}')">
                                            <strong>${opt.id.toUpperCase()}.</strong> ${opt.text}
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                            ${choice ? `
                                <div style="margin-top: 16px; padding: 16px; border-radius: 8px; background: ${choice.correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 217, 61, 0.1)'}; border-left: 3px solid ${choice.correct ? 'var(--green)' : 'var(--yellow)'};">
                                    <div style="font-weight: 600; margin-bottom: 8px; color: ${choice.correct ? 'var(--green)' : 'var(--yellow)'};">
                                        ${choice.correct ? '✓ Excellent choice!' : '⚠ Partial credit'} (+${choice.points} points)
                                    </div>
                                    <div style="color: var(--text-secondary); font-size: 0.9rem;">${choice.feedback}</div>
                                </div>
                            ` : ''}
                        </div>
                    `;
        }).join('')}
            </div>
        `;
    },

    init() {
        // Nothing special needed
    },

    selectOption(stepId, optionId) {
        const step = this.scenario.steps.find(s => s.id === stepId);
        const option = step.options.find(o => o.id === optionId);

        // Record choice
        this.choices.push({
            stepId: stepId,
            optionId: optionId,
            correct: option.correct,
            points: option.points,
            feedback: option.feedback
        });

        // Update score
        this.score += option.points;
        document.getElementById('current-score').textContent = this.score;

        // Highlight selected option
        document.querySelectorAll('.incident-option').forEach(el => {
            el.style.pointerEvents = 'none';
            if (el.dataset.option === optionId) {
                el.classList.add('selected');
                el.style.borderColor = option.correct ? 'var(--green)' : 'var(--yellow)';
                el.style.background = option.correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 217, 61, 0.1)';
            }
        });

        // Move to next step after delay
        setTimeout(() => {
            if (this.currentStep < this.scenario.steps.length - 1) {
                this.currentStep++;
                document.getElementById('step-counter').textContent = this.currentStep + 1;
                document.getElementById('incident-content').innerHTML = this.renderStep(this.currentStep);
            } else {
                this.complete();
            }
        }, 2000);
    },

    complete() {
        const feedback = this.choices.map((choice, idx) => {
            const step = this.scenario.steps[idx];
            return {
                correct: choice.correct,
                title: `Step ${idx + 1}: ${step.title}`,
                explanation: choice.correct
                    ? 'You made the optimal decision for this situation.'
                    : `Better choice: ${step.options.find(o => o.correct).text}`
            };
        });

        completeSimulation('incident-response', this.score, this.maxScore, feedback);
    }
};

// Export for global access
window.IncidentResponseSimulation = IncidentResponseSimulation;
