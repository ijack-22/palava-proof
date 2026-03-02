/**
 * Palava Proof — app.js
 * Calls the Flask backend for real scam detection.
 *
 * HOW THE API URL WORKS:
 * - In development: set window.API_BASE via a <script> in index.html, or it defaults to '' (same origin)
 * - In production on Railway: your frontend and backend are the same service,
 *   so relative URLs ('/api/check') work automatically.
 * - If you split frontend/backend into separate Railway services, set:
 *   window.API_BASE = 'https://your-backend.up.railway.app'
 *   in a <script> tag before this file loads, or use an env-injected config.
 */

const API_BASE = window.API_BASE || '';

// ─────────────────────────────────────────────
// DOM READY
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    const messageInput = document.getElementById('messageInput');
    const checkBtn     = document.getElementById('checkButton');
    const clearBtn     = document.getElementById('clearButton');
    const reportBtn    = document.getElementById('reportButton');
    const resultArea   = document.getElementById('result');
    const charCount    = document.getElementById('charCount');

    // Modal
    const modal        = document.getElementById('reportModal');
    const closeModal   = document.getElementById('closeModal');
    const submitReport = document.getElementById('submitReport');
    const reportFeedback = document.getElementById('reportFeedback');

    // ── Character counter ────────────────────────────────────
    messageInput.addEventListener('input', () => {
        const len = messageInput.value.length;
        charCount.textContent = `${len} character${len !== 1 ? 's' : ''}`;
    });

    // ── Check button ────────────────────────────────────────
    checkBtn.addEventListener('click', handleCheck);

    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) handleCheck();
    });

    // ── Clear button ─────────────────────────────────────────
    clearBtn.addEventListener('click', () => {
        messageInput.value = '';
        charCount.textContent = '0 characters';
        resultArea.classList.add('hidden');
        resultArea.innerHTML = '';
        messageInput.focus();
    });

    // ── Report modal ─────────────────────────────────────────
    reportBtn.addEventListener('click', () => {
        // Pre-fill if there's a message in the input
        const msg = messageInput.value.trim();
        if (msg) document.getElementById('reportContent').value = msg;
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    });

    closeModal.addEventListener('click', closeReportModal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeReportModal();
    });

    submitReport.addEventListener('click', handleReport);

    // ── Load recent scams ─────────────────────────────────────
    loadRecentScams();

    // ── Service Worker ────────────────────────────────────────
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/src/sw.js')
            .then(() => console.log('✅ SW registered'))
            .catch(err => console.warn('SW error:', err));
    }
});


// ─────────────────────────────────────────────
// CHECK MESSAGE — calls Flask API
// ─────────────────────────────────────────────
async function handleCheck() {
    const messageInput = document.getElementById('messageInput');
    const checkBtn     = document.getElementById('checkButton');
    const resultArea   = document.getElementById('result');

    const message = messageInput.value.trim();
    if (!message) {
        showInlineError(resultArea, 'Please paste a message to check.');
        return;
    }

    // Loading state
    checkBtn.disabled = true;
    checkBtn.innerHTML = '<div class="spinner" style="width:18px;height:18px;border-width:2px;margin:0 auto"></div>';
    resultArea.classList.remove('hidden');
    resultArea.innerHTML = `
        <div class="loading-result">
            <div class="spinner"></div>
            Analyzing message…
        </div>
    `;

    try {
        const res = await fetch(`${API_BASE}/api/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message }),
        });

        if (!res.ok) throw new Error(`Server error: ${res.status}`);

        const data = await res.json();
        renderResult(data, message);

    } catch (err) {
        console.error('API error:', err);
        // Fallback to offline detection if API unreachable
        const offlineResult = offlineAnalyze(message);
        offlineResult._offline = true;
        renderResult(offlineResult, message);
    } finally {
        checkBtn.disabled = false;
        checkBtn.innerHTML = '<span class="btn-icon">🔍</span> Check for Scam';
    }
}


// ─────────────────────────────────────────────
// RENDER RESULT
// ─────────────────────────────────────────────
function renderResult(data, originalMessage) {
    const resultArea = document.getElementById('result');

    const confidence = data.confidence || 0;
    const isScam = data.is_scam;
    const warnings = data.warnings || [];
    const tips = data.tips || [];
    const scamTypeLabel = data.scam_type_label || '';

    // Determine severity tier
    let tier, emoji, verdict;
    if (confidence >= 60) {
        tier = 'danger';
        emoji = '🚨';
        verdict = 'PALAVA DETECTED — Do not respond!';
    } else if (confidence >= 30) {
        tier = 'warning';
        emoji = '⚠️';
        verdict = 'Suspicious — Proceed with caution';
    } else {
        tier = 'safe';
        emoji = '✅';
        verdict = 'Looks safe — Stay alert';
    }

    // Warnings HTML
    let warningsHtml = '';
    if (warnings.length > 0) {
        warningsHtml = `
            <div class="warnings-block">
                <div class="warnings-title">⚑ Warning Signs Detected</div>
                ${warnings.map(w => `
                    <div class="warning-item">
                        <span class="warning-dot">▸</span>
                        <span>${escapeHtml(w)}</span>
                    </div>
                `).join('')}
            </div>
        `;
    }

    // Tips HTML
    let tipsHtml = '';
    if (tips.length > 0) {
        tipsHtml = `
            <div class="tips-block">
                <div class="tips-title">💡 How to stay safe</div>
                ${tips.map(t => `
                    <div class="tip-item">
                        <span class="tip-dot">▸</span>
                        <span>${escapeHtml(t)}</span>
                    </div>
                `).join('')}
            </div>
        `;
    }

    // Offline notice
    const offlineNotice = data._offline ? `
        <div style="font-size:0.78rem;color:var(--text-3);margin-bottom:12px;padding:8px 12px;background:var(--bg-3);border-radius:6px;">
            ⚡ Offline mode — result based on local analysis
        </div>
    ` : '';

    resultArea.innerHTML = `
        ${offlineNotice}
        <div class="status-card ${tier}">
            <div class="status-top">
                <div class="status-emoji">${emoji}</div>
                <div class="status-info">
                    <div class="status-verdict">${verdict}</div>
                    ${scamTypeLabel ? `<div class="status-type">${scamTypeLabel}</div>` : ''}
                    <div class="confidence-track">
                        <div class="confidence-fill" style="width: 0%" data-target="${confidence}"></div>
                    </div>
                    <div class="confidence-label">${confidence}% scam confidence</div>
                </div>
            </div>
        </div>

        ${warningsHtml}
        ${tipsHtml}

        <div class="message-preview">
            "${escapeHtml(originalMessage.substring(0, 120))}${originalMessage.length > 120 ? '…' : ''}"
        </div>

        <div class="result-actions">
            <button class="btn-feedback" onclick="sendFeedback('accurate')">👍 Accurate</button>
            <button class="btn-feedback" onclick="sendFeedback('inaccurate')">👎 Wrong result</button>
            <button class="btn-share-result" onclick="shareWarning()">📤 Share Warning</button>
        </div>
    `;

    // Animate confidence bar
    requestAnimationFrame(() => {
        const fill = resultArea.querySelector('.confidence-fill');
        if (fill) {
            setTimeout(() => {
                fill.style.width = fill.dataset.target + '%';
            }, 50);
        }
    });

    resultArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}


// ─────────────────────────────────────────────
// REPORT MODAL
// ─────────────────────────────────────────────
function closeReportModal() {
    document.getElementById('reportModal').classList.add('hidden');
    document.body.style.overflow = '';
}

async function handleReport() {
    const content  = document.getElementById('reportContent').value.trim();
    const type     = document.getElementById('reportType').value;
    const phone    = document.getElementById('reportPhone').value.trim();
    const url      = document.getElementById('reportUrl').value.trim();
    const submitBtn = document.getElementById('submitReport');
    const feedback  = document.getElementById('reportFeedback');

    if (!content) {
        showFeedback(feedback, 'error', 'Please describe the scam before submitting.');
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting…';
    feedback.classList.add('hidden');

    try {
        const res = await fetch(`${API_BASE}/api/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: content, type, phone_number: phone || null, url: url || null }),
        });

        if (!res.ok) throw new Error('Server error');
        const data = await res.json();

        showFeedback(feedback, 'success', `✅ ${data.message}`);

        // Reset form after 2s
        setTimeout(() => {
            document.getElementById('reportContent').value = '';
            document.getElementById('reportPhone').value   = '';
            document.getElementById('reportUrl').value     = '';
            closeReportModal();
            feedback.classList.add('hidden');
            loadRecentScams(); // Refresh list
        }, 2000);

    } catch (err) {
        showFeedback(feedback, 'error', '❌ Could not submit. Check your connection and try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Report 🇱🇷';
    }
}


// ─────────────────────────────────────────────
// RECENT SCAMS
// ─────────────────────────────────────────────
async function loadRecentScams() {
    const container = document.getElementById('recentScams');

    try {
        const res = await fetch(`${API_BASE}/api/recent-scams`);
        if (!res.ok) throw new Error('Failed');
        const data = await res.json();
        const scams = data.scams || [];

        if (!scams.length) {
            container.innerHTML = '<div class="empty-state">No community reports yet. Be the first to report a scam.</div>';
            return;
        }

        const typeLabels = {
            sms: '📱 SMS', whatsapp: '💬 WhatsApp',
            call: '📞 Call', link: '🔗 Link', sms_scam: '📱 SMS'
        };

        container.innerHTML = scams.map(s => `
            <div class="scam-card">
                <span class="scam-type-badge">${typeLabels[s.type] || s.type || 'Unknown'}</span>
                <div class="scam-info">
                    <div class="scam-preview">${escapeHtml((s.content || s.url || s.phone_number || 'No details').substring(0, 80))}</div>
                    <div class="scam-meta">
                        <span>Reported ${s.times_reported}×</span>
                        ${s.reported_at ? `<span>${formatDate(s.reported_at)}</span>` : ''}
                    </div>
                </div>
            </div>
        `).join('');

    } catch {
        container.innerHTML = '<div class="empty-state">Could not load recent reports. Check your connection.</div>';
    }
}


// ─────────────────────────────────────────────
// SHARE WARNING
// ─────────────────────────────────────────────
window.shareWarning = function() {
    const input = document.getElementById('messageInput').value.trim();
    const shareText = `⚠️ Palava Proof Scam Alert 🛡️\n\nSuspicious message:\n"${input.substring(0, 200)}"\n\nProtect yourself — check scams at Palava Proof, Liberia's Community Scam Shield`;

    if (navigator.share) {
        navigator.share({ title: 'Palava Proof Scam Alert', text: shareText })
            .catch(() => fallbackCopy(shareText));
    } else {
        fallbackCopy(shareText);
    }
};

function fallbackCopy(text) {
    navigator.clipboard.writeText(text)
        .then(() => showToast('📋 Copied to clipboard!'))
        .catch(() => showToast('Could not copy — please share manually.'));
}


// ─────────────────────────────────────────────
// FEEDBACK
// ─────────────────────────────────────────────
window.sendFeedback = function(type) {
    showToast(type === 'accurate'
        ? '🙏 Thank you! This helps us improve.'
        : '📝 Got it — we\'ll review this detection.'
    );
};


// ─────────────────────────────────────────────
// OFFLINE FALLBACK ANALYZER
// Used when API is unreachable (e.g. no internet)
// ─────────────────────────────────────────────
function offlineAnalyze(message) {
    const m = message.toLowerCase();
    let confidence = 0;
    const warnings = [];

    const checks = [
        [/(won|prize|winner|lottery|congratulations)/i,       25, 'Claims you won something'],
        [/(momo|mobile money|lonestar cash|orange money)/i,   20, 'References mobile money'],
        [/(verify|confirm|update).{0,30}(account|details)/i,  20, 'Asks to verify account'],
        [/(urgent|immediately|limited time)/i,                 10, 'Creates urgency'],
        [/(bit\.ly|tinyurl|ow\.ly)/i,                         20, 'Contains shortened URL'],
        [/(registration|processing|training).{0,10}fee/i,     25, 'Asks for upfront fee'],
        [/(free airtime|free data)/i,                         15, 'Promises free airtime/data'],
        [/(pin|password|otp).{0,20}(send|reply|share)/i,      30, 'Asks for PIN or OTP'],
    ];

    checks.forEach(([re, score, label]) => {
        if (re.test(m)) { confidence += score; warnings.push(label); }
    });

    return {
        is_scam: confidence >= 30,
        confidence: Math.min(confidence, 100),
        scam_type: null,
        scam_type_label: null,
        warnings,
        tips: ['Never share your PIN or OTP with anyone.', 'When in doubt, don\'t respond.'],
    };
}


// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatDate(dateStr) {
    try {
        const d = new Date(dateStr);
        return d.toLocaleDateString('en-LR', { month: 'short', day: 'numeric' });
    } catch { return ''; }
}

function showFeedback(el, type, message) {
    el.className = `report-feedback ${type}`;
    el.textContent = message;
}

function showInlineError(container, message) {
    container.classList.remove('hidden');
    container.innerHTML = `<div class="error-result">⚠️ ${message}</div>`;
}

function showToast(message) {
    const existing = document.getElementById('palava-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'palava-toast';
    toast.textContent = message;
    Object.assign(toast.style, {
        position: 'fixed', bottom: '24px', left: '50%',
        transform: 'translateX(-50%)',
        background: '#1C2128', color: '#E6EDF3',
        border: '1px solid rgba(255,255,255,0.12)',
        padding: '12px 20px', borderRadius: '10px',
        fontSize: '0.88rem', zIndex: '9999',
        boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
        animation: 'fadeUp 0.25s ease',
        whiteSpace: 'nowrap',
    });

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

window.addEventListener('online',  () => showToast('📡 Back online'));
window.addEventListener('offline', () => showToast('⚡ Offline mode — using local detection'));
