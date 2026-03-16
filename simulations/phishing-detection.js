/**
 * Phishing Detection Simulation
 * Review emails and identify phishing attempts
 */

const PhishingSimulation = {
    emails: [],
    currentEmailIndex: 0,
    results: [],

    emailScenarios: [
        {
            id: 1,
            sender: 'IT-Support@c0rp-security.com',
            senderDisplay: 'IT Support Team',
            subject: 'URGENT: Password Expiration Notice',
            date: 'Today at 9:15 AM',
            body: `Dear Employee,

Your corporate password will expire in 24 hours. To avoid losing access to your account, please update your password immediately by clicking the link below:

[Update Password Now](http://corp-security-update.tk/reset?user={{email}})

If you do not update your password within 24 hours, your account will be suspended and you will need to contact IT support to regain access.

Best regards,
IT Security Team
Corporate Security Division`,
            isPhishing: true,
            redFlags: [
                'Suspicious sender domain (c0rp-security.com with zero instead of "o")',
                'Creates urgency with threats of account suspension',
                'Link uses suspicious TLD (.tk) and doesn\'t match corporate domain',
                'Generic greeting instead of using your name'
            ]
        },
        {
            id: 2,
            sender: 'notifications@amazon.com',
            senderDisplay: 'Amazon.com',
            subject: 'Your order #112-3847562-9283746 has shipped',
            date: 'Today at 10:30 AM',
            body: `Hello,

Great news! Your package is on its way.

Order #112-3847562-9283746
Estimated delivery: January 18, 2024

Track your package:
[Track Package](https://www.amazon.com/gp/your-account/order-details?orderID=112-3847562-9283746)

If you have any questions about your order, visit our Help pages.

Thanks for shopping with us!
Amazon.com`,
            isPhishing: false,
            redFlags: []
        },
        {
            id: 3,
            sender: 'secure-alert@bankofamerica.com.suspicious-domain.net',
            senderDisplay: 'Bank of America Security',
            subject: 'Suspicious Activity Detected - Immediate Action Required',
            date: 'Today at 11:45 AM',
            body: `SECURITY ALERT

Dear Valued Customer,

We have detected unusual login activity on your Bank of America account from an unrecognized device in Russia.

If this was not you, please verify your identity immediately to prevent unauthorized access:

[Verify My Identity](http://boa-secure-verify.xyz/login)

Location: Moscow, Russia
Device: Unknown Android Device
Time: January 15, 2024 at 3:42 AM EST

If you do not verify within 2 hours, your account will be temporarily frozen for your protection.

Bank of America Security Team
1-800-432-1000`,
            isPhishing: true,
            redFlags: [
                'Sender domain is actually "suspicious-domain.net" disguised as Bank of America',
                'Link goes to xyz domain, not bankofamerica.com',
                'Creates panic with claims of suspicious activity in Russia',
                'Time pressure with 2-hour deadline',
                'Real banks never ask you to verify via email links'
            ]
        },
        {
            id: 4,
            sender: 'calendar-noreply@google.com',
            senderDisplay: 'Google Calendar',
            subject: 'Invitation: Team Standup @ Weekly',
            date: 'Yesterday at 4:00 PM',
            body: `You have been invited to the following event:

Team Standup
When: Every Monday at 9:00 AM - 9:30 AM
Where: Conference Room B / Google Meet

Organizer: sarah.chen@yourcompany.com

Going? Yes - Maybe - No

View your calendar: https://calendar.google.com

Google Calendar`,
            isPhishing: false,
            redFlags: []
        },
        {
            id: 5,
            sender: 'admin@microsoft-365-support.co',
            senderDisplay: 'Microsoft 365 Admin',
            subject: 'Your Microsoft 365 subscription has been cancelled',
            date: 'Today at 8:00 AM',
            body: `Microsoft 365 Notification

Hello,

Your Microsoft 365 subscription has been cancelled due to a payment issue. All your files in OneDrive and Outlook emails will be permanently deleted within 48 hours.

To restore your subscription and prevent data loss, please update your payment information:

[Restore Subscription](http://microsoft365-restore.click/payment)

If you believe this is an error, contact our support team immediately.

Microsoft 365 Support Team`,
            isPhishing: true,
            redFlags: [
                'Fake domain "microsoft-365-support.co" instead of microsoft.com',
                'Threat of permanent data deletion creates panic',
                'Suspicious link domain (.click TLD)',
                'Microsoft would never threaten immediate deletion',
                'Payment issues are handled through account.microsoft.com'
            ]
        },
        {
            id: 6,
            sender: 'noreply@github.com',
            senderDisplay: 'GitHub',
            subject: '[GitHub] A new device signed in to your account',
            date: 'Today at 2:33 PM',
            body: `Hey there,

A new device just signed in to your GitHub account.

Device: Chrome on Mac OS X
Location: San Francisco, CA, USA
Time: January 15, 2024 at 2:33 PM PST
IP Address: 104.28.xxx.xxx

If this was you, you can safely ignore this email.

If this wasn't you, please secure your account:
https://github.com/settings/security

Thanks,
The GitHub Team

You're receiving this email because a new device signed in to your account.
Manage email preferences: https://github.com/settings/notifications`,
            isPhishing: false,
            redFlags: []
        }
    ],

    render() {
        // Shuffle emails for variety
        // Fixed order for competition fairness (no randomization)
        this.emails = [...this.emailScenarios];
        this.currentEmailIndex = 0;
        this.results = [];

        return `
            <div class="simulation-header">
                <h2 class="simulation-title">Phishing Detection Training</h2>
                <div class="simulation-timer">
                    <span id="email-counter">Email 1 of ${this.emails.length}</span>
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
                <p>Review each email carefully. Examine the sender address, subject line, and content for signs of phishing. Mark each email as either SAFE or PHISHING.</p>
            </div>
            
            <div class="simulation-content">
                <div class="email-container">
                    <div class="email-list" id="email-list">
                        ${this.emails.map((email, idx) => `
                            <div class="email-item ${idx === 0 ? 'active' : ''}" data-index="${idx}" onclick="PhishingSimulation.selectEmail(${idx})">
                                <div class="email-sender">${email.senderDisplay}</div>
                                <div class="email-subject">${email.subject}</div>
                            </div>
                        `).join('')}
                    </div>
                    <div class="email-preview" id="email-preview">
                        ${this.renderEmail(this.emails[0])}
                    </div>
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
                <div id="progress-indicator" style="color: var(--text-secondary);">
                    ${this.results.length} of ${this.emails.length} reviewed
                </div>
            </div>
        `;
    },

    renderEmail(email) {
        const alreadyAnswered = this.results.find(r => r.id === email.id);

        return `
            <div class="email-header">
                <div class="email-header-row">
                    <span class="email-header-label">From:</span>
                    <span class="email-header-value">${email.senderDisplay} &lt;${email.sender}&gt;</span>
                </div>
                <div class="email-header-row">
                    <span class="email-header-label">Subject:</span>
                    <span class="email-header-value">${email.subject}</span>
                </div>
                <div class="email-header-row">
                    <span class="email-header-label">Date:</span>
                    <span class="email-header-value">${email.date}</span>
                </div>
            </div>
            <div class="email-body">
                ${email.body.replace(/\n/g, '<br>').replace(/\[(.*?)\]\((.*?)\)/g, '<a href="#" style="color: var(--cyan);">$1</a>')}
            </div>
            <div class="email-actions">
                ${alreadyAnswered ? `
                    <div style="padding: 12px; border-radius: 8px; background: ${alreadyAnswered.correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 56, 96, 0.1)'}; color: ${alreadyAnswered.correct ? 'var(--green)' : 'var(--red)'};">
                        ${alreadyAnswered.correct ? '✓ Correct!' : '✗ Incorrect'} - This email is ${email.isPhishing ? 'PHISHING' : 'SAFE'}
                    </div>
                ` : `
                    <button class="btn btn-safe" onclick="PhishingSimulation.markEmail(${email.id}, false)">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <polyline points="20 6 9 17 4 12"/>
                        </svg>
                        Mark as Safe
                    </button>
                    <button class="btn btn-phishing" onclick="PhishingSimulation.markEmail(${email.id}, true)">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        Mark as Phishing
                    </button>
                `}
            </div>
        `;
    },

    init() {
        // Nothing special needed for init
    },

    selectEmail(index) {
        this.currentEmailIndex = index;

        // Update email list selection
        document.querySelectorAll('.email-item').forEach((item, idx) => {
            item.classList.toggle('active', idx === index);
        });

        // Update preview
        document.getElementById('email-preview').innerHTML = this.renderEmail(this.emails[index]);
        document.getElementById('email-counter').textContent = `Email ${index + 1} of ${this.emails.length}`;
    },

    markEmail(emailId, markedAsPhishing) {
        const email = this.emails.find(e => e.id === emailId);
        const correct = email.isPhishing === markedAsPhishing;

        this.results.push({
            id: emailId,
            correct: correct,
            markedAsPhishing: markedAsPhishing,
            actualPhishing: email.isPhishing
        });

        // Update the current email view
        document.getElementById('email-preview').innerHTML = this.renderEmail(email);

        // Update progress
        document.getElementById('progress-indicator').textContent = `${this.results.length} of ${this.emails.length} reviewed`;

        // Style the email item in the list
        const emailItem = document.querySelector(`.email-item[data-index="${this.currentEmailIndex}"]`);
        emailItem.style.borderColor = correct ? 'var(--green)' : 'var(--red)';
        emailItem.style.background = correct ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 56, 96, 0.1)';

        // Check if all emails are reviewed
        if (this.results.length === this.emails.length) {
            setTimeout(() => this.complete(), 1000);
        } else {
            // Auto-advance to next unreviewed email
            const nextIndex = this.emails.findIndex((e, idx) =>
                idx > this.currentEmailIndex && !this.results.find(r => r.id === e.id)
            );
            if (nextIndex !== -1) {
                setTimeout(() => this.selectEmail(nextIndex), 500);
            }
        }
    },

    complete() {
        const correctCount = this.results.filter(r => r.correct).length;
        const maxScore = 300;
        const score = Math.round((correctCount / this.emails.length) * maxScore);

        const feedback = this.emails.map(email => {
            const result = this.results.find(r => r.id === email.id);
            return {
                correct: result.correct,
                title: result.correct
                    ? `✓ ${email.senderDisplay}: Correctly identified as ${email.isPhishing ? 'phishing' : 'safe'}`
                    : `✗ ${email.senderDisplay}: Incorrectly marked`,
                explanation: email.isPhishing
                    ? `Red flags: ${email.redFlags.join('; ')}`
                    : 'This was a legitimate email from a verified sender.'
            };
        });

        completeSimulation('phishing', score, maxScore, feedback);
    }
};

// Export for global access
window.PhishingSimulation = PhishingSimulation;
