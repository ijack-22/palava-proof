// Palava Proof - Modern UX Version
console.log('🔥 Palava Proof loaded!');

// ==================== GLOBAL FUNCTIONS ====================
window.markAccurate = function() {
    alert('🙏 Thank you for your feedback! This helps improve Palava Proof.');
    return false;
};

window.markInaccurate = function() {
    alert('📝 Thank you for letting us know. We\'ll review this message.');
    return false;
};

window.shareResult = function() {
    const messageInput = document.getElementById('messageInput');
    const message = messageInput ? messageInput.value.trim() : '';
    
    if (!message) {
        alert('No message to share. Please check a message first.');
        return;
    }
    
    const shareText = `⚠️ Palava Proof Scam Alert ⚠️\n\nSuspicious message: "${message}"\n\nCheck scams at Palava Proof - Liberia's Community Scam Shield`;
    
    if (navigator.share) {
        navigator.share({
            title: 'Palava Proof Scam Alert',
            text: shareText,
            url: window.location.href,
        }).catch(() => copyToClipboard(shareText));
    } else {
        copyToClipboard(shareText);
    }
    return false;
};

function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        document.execCommand('copy');
        alert('📋 Warning copied to clipboard! Share with friends.');
    } catch (err) {
        alert('Could not copy. Please share manually.');
    }
    
    document.body.removeChild(textarea);
}

// ==================== MAIN APP ====================
document.addEventListener('DOMContentLoaded', () => {
    console.log('📱 DOM ready');
    
    // Get DOM elements
    const messageInput = document.getElementById('messageInput');
    const checkBtn = document.getElementById('checkButton');
    const clearBtn = document.getElementById('clearButton');
    const reportBtn = document.getElementById('reportButton');
    const resultBox = document.getElementById('result');
    
    // Clear button functionality
    if (clearBtn && messageInput) {
        clearBtn.addEventListener('click', () => {
            messageInput.value = '';
            resultBox.classList.add('hidden');
            messageInput.focus();
        });
    }
    
    // Check button functionality
    if (checkBtn && messageInput && resultBox) {
        checkBtn.addEventListener('click', () => {
            const message = messageInput.value.trim();
            
            if (!message) {
                alert('Please paste a message to check');
                return;
            }
            
            // Show loading state
            resultBox.classList.remove('hidden');
            resultBox.innerHTML = '<div class="loading">Analyzing message...</div>';
            
            // Small delay to show loading (feels more responsive)
            setTimeout(() => {
                const result = analyzeMessage(message);
                displayResult(result, message);
            }, 300);
        });
    }
    
    // Report button functionality
    if (reportBtn && messageInput) {
        reportBtn.addEventListener('click', () => {
            const message = messageInput.value.trim();
            if (message) {
                alert(`📢 Thank you for reporting!\n\nWe'll investigate: "${message.substring(0, 50)}..."`);
            } else {
                alert('Please paste the scam message in the box above before reporting.');
            }
        });
    }
    
    // Ctrl+Enter shortcut
    if (messageInput && checkBtn) {
        messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.ctrlKey) {
                checkBtn.click();
            }
        });
    }
    
    // Service Worker
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js')
            .then(() => console.log('✅ Service Worker registered'))
            .catch(err => console.log('❌ Service Worker error:', err));
    }
});

// ==================== SCAM DETECTION ====================
function analyzeMessage(message) {
    const messageLower = message.toLowerCase();
    
    // Scam indicators with categories
    const indicators = {
        urgency: ['urgent', 'immediately', 'now', 'today', 'limited', 'expires', 'deadline', 'action required'],
        prizes: ['won', 'prize', 'winner', 'congratulations', 'awarded', 'selected', 'lucky'],
        free: ['free', 'gift', 'bonus', 'reward', 'claim', 'discount', 'offer'],
        account: ['account', 'verify', 'verification', 'update', 'locked', 'suspended', 'restricted'],
        money: ['money', 'cash', 'transfer', 'payment', 'bank', 'orange money', 'mtn', 'loan'],
        links: ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'click', 'link'],
        phone: ['077', '088', '055', '056', '231']
    };
    
    let findings = [];
    let confidence = 0;
    
    // Check each category
    if (indicators.urgency.some(word => messageLower.includes(word))) {
        findings.push({ type: 'urgency', text: 'Creates false urgency' });
        confidence += 15;
    }
    
    if (indicators.prizes.some(word => messageLower.includes(word))) {
        findings.push({ type: 'prize', text: 'Claims you won something' });
        confidence += 20;
    }
    
    if (indicators.free.some(word => messageLower.includes(word))) {
        findings.push({ type: 'free', text: 'Offers free gifts/money' });
        confidence += 15;
    }
    
    if (indicators.account.some(word => messageLower.includes(word))) {
        findings.push({ type: 'account', text: 'Asks to verify account' });
        confidence += 20;
    }
    
    if (indicators.money.some(word => messageLower.includes(word))) {
        findings.push({ type: 'money', text: 'Mentions money/transfers' });
        confidence += 10;
    }
    
    // Check for shortened URLs
    if (indicators.links.some(link => messageLower.includes(link))) {
        findings.push({ type: 'link', text: 'Contains shortened URL' });
        confidence += 25;
    }
    
    // Check for Liberian phone numbers
    if (indicators.phone.some(code => message.includes(code))) {
        findings.push({ type: 'phone', text: 'Contains Liberian phone number' });
        confidence += 15;
    }
    
    // Check for multiple exclamation marks or ALL CAPS
    if (message.includes('!!!') || (message.match(/[A-Z]/g) || []).length > message.length * 0.4) {
        findings.push({ type: 'shouting', text: 'Uses excessive urgency' });
        confidence += 10;
    }
    
    // Calculate final confidence and status
    confidence = Math.min(confidence, 100);
    
    let status = 'safe';
    if (confidence >= 60) {
        status = 'danger';
    } else if (confidence >= 30) {
        status = 'suspicious';
    }
    
    return {
        status: status,
        confidence: confidence,
        findings: findings,
        isScam: confidence >= 30
    };
}

// ==================== DISPLAY RESULTS ====================
function displayResult(result, originalMessage) {
    const resultBox = document.getElementById('result');
    
    // Status configuration
    const statusConfig = {
        safe: {
            icon: '✅',
            title: 'This message appears safe',
            class: 'safe',
            bgColor: '#D1FAE5',
            textColor: '#065F46'
        },
        suspicious: {
            icon: '⚠️',
            title: 'Suspicious - Check carefully',
            class: 'suspicious',
            bgColor: '#FEF3C7',
            textColor: '#92400E'
        },
        danger: {
            icon: '🚨',
            title: 'PALAVA DETECTED! Do not respond!',
            class: 'danger',
            bgColor: '#FEE2E2',
            textColor: '#991B1B'
        }
    };
    
    const config = statusConfig[result.status];
    
    // Build warnings HTML
    let warningsHtml = '';
    if (result.findings.length > 0) {
        warningsHtml = '<div class="warnings-list"><h4>⚠️ Warning Signs Found:</h4>';
        result.findings.forEach(finding => {
            warningsHtml += `
                <div class="warning-item">
                    <span class="warning-icon">⚠️</span>
                    <span class="warning-text">${finding.text}</span>
                </div>
            `;
        });
        warningsHtml += '</div>';
    }
    
    // Build confidence meter
    const confidenceColor = result.confidence > 60 ? '#EF4444' : (result.confidence > 30 ? '#F59E0B' : '#10B981');
    
    // Full result HTML
    resultBox.innerHTML = `
        <div class="status-badge ${config.class}" style="background: ${config.bgColor}; color: ${config.textColor};">
            <span class="status-icon">${config.icon}</span>
            <div class="status-content">
                <div class="status-title">${config.title}</div>
                <div class="status-confidence">${result.confidence}% confidence score</div>
            </div>
        </div>
        
        ${warningsHtml}
        
        <div style="margin: 20px 0; padding: 15px; background: #F3F4F6; border-radius: 8px;">
            <div style="font-size: 0.9em; color: #6B7280; margin-bottom: 8px;">📝 Message analyzed:</div>
            <div style="font-style: italic; color: #374151;">"${originalMessage.substring(0, 150)}${originalMessage.length > 150 ? '...' : ''}"</div>
        </div>
        
        <div class="feedback-section">
            <div class="feedback-buttons">
                <button class="btn-feedback positive" onclick="window.markAccurate()">
                    <span>👍</span> Yes, accurate
                </button>
                <button class="btn-feedback negative" onclick="window.markInaccurate()">
                    <span>👎</span> No, needs review
                </button>
            </div>
            <button class="btn-share" onclick="window.shareResult()">
                <span>📤</span> Share Warning
            </button>
        </div>
    `;
    
    // Scroll to result smoothly
    resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ==================== OFFLINE STORAGE ====================
function openDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('PalavaProofDB', 1);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains('scamReports')) {
                db.createObjectStore('scamReports', { keyPath: 'id', autoIncrement: true });
            }
        };
    });
}

// ==================== SYNC WHEN ONLINE ====================
window.addEventListener('online', () => {
    console.log('📡 Back online - ready to sync');
    // Could add auto-sync here later
});
