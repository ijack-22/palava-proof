import os
import re
import sqlite3
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
CORS(app, origins=allowed_origins)

DB_PATH = os.path.join(os.path.dirname(__file__), 'palava_proof.db')

# ── Database ────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        phone TEXT,
        url TEXT,
        scam_type TEXT,
        reported_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS phone_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT UNIQUE,
        times_reported INTEGER DEFAULT 1,
        scam_type TEXT,
        last_reported TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS url_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        times_reported INTEGER DEFAULT 1,
        last_reported TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

# ── Scam Patterns ───────────────────────────────────────────
# Format: (pattern, weight, scam_type, tip)
PATTERNS = [
    # ── MOBILE MONEY ──
    (r'send.*pin|share.*pin|pin.*momo|momo.*pin|give.*pin', 30, 'mobile_money', 'Never share your PIN with anyone — not even MTN or Lonestar staff.'),
    (r'mtn.*momo|momo.*transfer|lonestar.*cash|orange.*money', 15, 'mobile_money', 'Verify all mobile money requests by calling the sender directly.'),
    (r'reverse.*transaction|wrong.*transfer|send back.*money|secret.*code.*reverse|reverse.*back|refund.*momo', 25, 'mobile_money', 'Legitimate wrong transfers are reversed by the network — you never send money back.'),
    (r'agent.*send.*money|momo.*agent.*request|transfer.*agent', 20, 'mobile_money', 'Real agents never ask you to send money to complete a transaction.'),
    (r'momo.*hack|account.*hack.*momo|your.*momo.*compromised', 25, 'mobile_money', 'This is a fear tactic to make you act without thinking.'),
    (r'dial.*\*1[0-9]{2}\*|ussd.*code.*send|press.*\*[0-9]+\*', 20, 'mobile_money', 'Never dial USSD codes sent to you by strangers — they can transfer your money.'),
    (r'momo.*balance.*low|top.*up.*momo.*urgent|recharge.*momo', 15, 'mobile_money', 'Unsolicited recharge requests are a common scam tactic.'),
    (r'lonestar.*pin|lonestar.*transfer.*code|lonestar.*agent.*send', 25, 'mobile_money', 'Lonestar Cell will never ask for your PIN via SMS or WhatsApp.'),
    (r'orange.*money.*pin|orange.*transfer.*code', 25, 'mobile_money', 'Orange Money will never request your PIN through a message.'),
    (r'airtime.*transfer.*fee|send.*airtime.*get.*cash', 20, 'mobile_money', 'Airtime-for-cash schemes are almost always scams.'),

    # ── LOTTERY / PRIZE ──
    (r'you.*won|winner.*selected|congratulations.*prize|claim.*prize|lucky.*winner', 25, 'lottery', 'You cannot win a lottery you never entered.'),
    (r'send.*fee.*claim|pay.*tax.*prize|processing.*fee.*win|clearance.*fee', 30, 'lottery', 'Legitimate prizes never require upfront fees.'),
    (r'secret.*win|tell.*nobody|keep.*confidential.*prize|don.*tell.*anyone', 20, 'lottery', 'Real prizes are never secret — this secrecy is a pressure tactic.'),
    (r'\$[0-9,]+.*prize|\$[0-9,]+.*won|usd.*[0-9]+.*claim', 20, 'lottery', 'Dollar prize claims via SMS are overwhelmingly fraudulent.'),
    (r'liberia.*lottery|national.*lottery.*liberia|libtelco.*prize', 25, 'lottery', 'Verify any lottery directly with the official organization — not through the message.'),
    (r'google.*lottery|facebook.*lottery|whatsapp.*prize|telegram.*winner', 30, 'lottery', 'Google, Facebook, WhatsApp and Telegram do not run cash lotteries.'),
    (r'claim.*within.*hours|prize.*expires.*today|collect.*before.*midnight', 25, 'lottery', 'Artificial urgency is designed to stop you from thinking clearly.'),
    (r'ref.*number.*prize|ticket.*number.*won|lucky.*number.*selected', 20, 'lottery', 'Fake reference numbers are used to make scams seem legitimate.'),

    # ── FAKE JOBS ──
    (r'whatsapp.*job|job.*whatsapp|recruiter.*whatsapp|hiring.*whatsapp', 20, 'job_scam', 'Legitimate employers do not recruit solely via WhatsApp.'),
    (r'work.*home.*earn|earn.*daily.*usd|make.*money.*online.*liberia|earn.*per.*day', 20, 'job_scam', 'Work-from-home schemes promising quick USD earnings are almost always scams.'),
    (r'un.*job|ngo.*hiring|unicef.*recruit|undp.*recruit|undp.*liberia|world.*bank.*job', 25, 'job_scam', 'Verify UN/NGO jobs only at their official websites — never through WhatsApp.'),
    (r'upfront.*fee.*job|pay.*register.*job|training.*fee.*employment|registration.*fee.*work', 30, 'job_scam', 'Legitimate employers never ask you to pay to get a job.'),
    (r'data.*entry.*job.*liberia|typing.*job.*earn|copy.*paste.*earn', 20, 'job_scam', 'Data entry and typing jobs that pay unusually well are almost always scams.'),
    (r'ambassador.*program.*earn|brand.*ambassador.*fee|influencer.*job.*pay', 20, 'job_scam', 'Paid ambassador programs that require upfront fees are scams.'),
    (r'mining.*investment.*liberia|gold.*investment.*liberia|diamond.*invest', 25, 'job_scam', 'Natural resource investment schemes targeting Liberians are a known fraud pattern.'),
    (r'cv.*fee.*apply|resume.*fee.*submit|application.*fee.*job', 25, 'job_scam', 'No legitimate employer charges application or CV submission fees.'),
    (r'salary.*[0-9]+.*usd.*week|earn.*[0-9]+.*dollar.*day|paid.*weekly.*cash', 20, 'job_scam', 'Unrealistic salary promises are the hallmark of job scams.'),

    # ── PHISHING ──
    (r'account.*suspend|verify.*account.*now|click.*link.*verify|account.*block', 25, 'phishing', 'Banks and telecoms never ask you to verify via SMS link.'),
    (r'bit\.ly|tinyurl|t\.co\/|goo\.gl|ow\.ly|is\.gd|tiny\.cc', 15, 'phishing', 'Shortened URLs in urgent messages are a major red flag — do not click.'),
    (r'mtn-liberia\.com|lonestar-cash\.net|libtelco-verify|mtn\.com\.lr-[a-z]', 30, 'phishing', 'This appears to be a fake website impersonating a Liberian telecom.'),
    (r'act.*now.*expire|urgent.*respond|limited.*time.*offer|respond.*immediately', 15, 'phishing', 'Urgency is a classic manipulation tactic — slow down and verify.'),
    (r'password.*reset.*link|enter.*otp.*website|otp.*expire|your.*otp.*is', 25, 'phishing', 'Never enter OTPs on websites you reached through a message link.'),
    (r'confirm.*details.*bank|update.*account.*information|verify.*identity.*link', 25, 'phishing', 'Your bank will never ask you to confirm details via a message link.'),
    (r'sim.*swap.*verify|sim.*upgrade.*click|network.*upgrade.*link', 25, 'phishing', 'SIM swap scams often use fake upgrade messages — contact your carrier directly.'),
    (r'login.*here.*urgent|sign.*in.*verify.*account|access.*restored.*click', 25, 'phishing', 'Never log into accounts through links sent via SMS or WhatsApp.'),

    # ── ROMANCE / ADVANCE FEE ──
    (r'send.*money.*love|transfer.*money.*relationship|gift.*money.*friend', 25, 'romance_scam', 'Someone you met online asking for money is almost always a scam.'),
    (r'stranded.*airport|stuck.*customs|emergency.*money.*transfer', 30, 'romance_scam', 'The "stranded traveler" story is one of the oldest advance fee scams.'),
    (r'inheritance.*share|dead.*relative.*money|unclaimed.*funds.*liberia', 30, 'advance_fee', 'Inheritance and unclaimed funds schemes are classic advance fee (419) scams.'),
    (r'diplomat.*package|customs.*clearance.*fee|delivery.*package.*fee', 25, 'advance_fee', 'Package delivery fees requested via message are almost always advance fee scams.'),

    # ── INVESTMENT SCAMS ──
    (r'double.*money|invest.*get.*double|100.*%.*return|100%.*profit|guaranteed.*profit|guaranteed.*return', 30, 'investment', 'No legitimate investment guarantees doubled returns — this is a Ponzi scheme.'),
    (r'crypto.*invest.*liberia|bitcoin.*profit.*guaranteed|forex.*signal.*group', 25, 'investment', 'Cryptocurrency investment groups promising guaranteed returns are scams.'),
    (r'pyramid.*scheme|referral.*bonus.*unlimited|join.*earn.*recruit', 25, 'investment', 'Schemes where earnings depend on recruiting others are pyramid schemes.'),

    # ── URL SECURITY ──
    (r'http://[^s]+', 30, 'phishing', 'This link uses HTTP (not HTTPS) — it is insecure and commonly used in scams. Never click it.'),
    (r'visit.*http|click.*http|go.*to.*http|collect.*http|claim.*http', 35, 'phishing', 'Scammers use HTTP links to steal your information. Legitimate sites always use HTTPS.'),
    (r'rnicrosoft|arnazon|gooogle|faceb00k|paypa1|rnicr0soft|micros0ft|micosoft', 35, 'phishing', 'This URL is impersonating a known brand — this is a phishing attack.'),
    (r'you.*won.*gift|won.*yourself|gift.*collect|collect.*winning|collect.*prize', 30, 'lottery', 'Unsolicited gift or prize notifications are almost always scams.'),
    (r'winings|winnigs|priize|gigt|lotterry|competiton', 25, 'phishing', 'Deliberate misspellings are used by scammers to bypass spam filters.'),

    # ── LIBERIA-SPECIFIC ──
    (r'\+231.*prize|\+231.*won|231.*lucky|\+231.*claim', 20, 'lottery', 'Liberian phone numbers used in prize notifications are a common scam pattern.'),
    (r'liberiabank.*verify|lbdi.*urgent|ecobank.*liberia.*click', 25, 'phishing', 'Banks in Liberia will never ask you to verify via SMS link.'),
    (r'ministry.*liberia.*payment|government.*liberia.*transfer|mof\.gov\.lr', 25, 'phishing', 'Government payments in Liberia are never processed via SMS links.'),
]

SCAM_LABELS = {
    'mobile_money': 'Mobile Money Fraud',
    'lottery': 'Lottery / Prize Scam',
    'job_scam': 'Fake Job Offer',
    'phishing': 'Phishing / Fake Website',
    'romance_scam': 'Romance Scam',
    'advance_fee': 'Advance Fee (419) Scam',
    'investment': 'Investment / Ponzi Scam',
}

# ── Suspicious URL patterns ─────────────────────────────────
SUSPICIOUS_DOMAINS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl', r'ow\.ly', r'is\.gd',
    r'mtn-liberia', r'lonestar-cash', r'libtelco-verify',
    r'liberiabank-verify', r'lbdi-online', r'ecobank-lr',
]

SUSPICIOUS_TLD = ['.xyz', '.top', '.click', '.loan', '.work', '.online', '.site']

def analyze_url(url):
    score = 0
    flags = []
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.lower()

        for pattern in SUSPICIOUS_DOMAINS:
            if re.search(pattern, domain):
                score += 30
                flags.append(f'Suspicious domain: {domain}')
                break

        for tld in SUSPICIOUS_TLD:
            if domain.endswith(tld):
                score += 20
                flags.append(f'High-risk domain extension: {tld}')
                break

        # Check blacklist
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT times_reported FROM url_blacklist WHERE domain = ?', (domain,))
        row = c.fetchone()
        conn.close()
        if row:
            score += min(row[0] * 10, 40)
            flags.append(f'Reported by community {row[0]} time(s)')

        # IP address instead of domain name
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            score += 25
            flags.append('Uses raw IP address instead of domain name')

        # Very long subdomain (common in phishing)
        if domain.count('.') > 3:
            score += 15
            flags.append('Unusually complex domain structure')

    except Exception:
        pass
    return min(score, 60), flags

def check_phone_blacklist(text):
    phones = re.findall(r'(\+?231[0-9]{7,9}|0[0-9]{8,9})', text)
    score = 0
    flags = []
    if phones:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        for phone in phones:
            c.execute('SELECT times_reported, scam_type FROM phone_blacklist WHERE phone = ?', (phone,))
            row = c.fetchone()
            if row:
                score += min(row[0] * 15, 45)
                flags.append(f'{phone} reported {row[0]} time(s) for {row[1]}')
        conn.close()
    return min(score, 45), flags

# ── Semantic boosters ───────────────────────────────────────
def semantic_boost(message):
    """Extra scoring for combinations of suspicious signals"""
    score = 0
    msg = message.lower()

    urgency = bool(re.search(r'urgent|immediately|now|today|hurry|quick|fast|expire', msg))
    money = bool(re.search(r'money|cash|usd|dollar|momo|transfer|send|pay|fee', msg))
    prize = bool(re.search(r'won|winner|prize|lottery|lucky|congratulation', msg))
    secrecy = bool(re.search(r'secret|nobody|confidential|don.t tell|private', msg))
    personal = bool(re.search(r'pin|password|otp|code|account|verify|confirm', msg))
    link = bool(re.search(r'http|www\.|click|link|tap here', msg))

    if urgency and money: score += 15
    if prize and money: score += 20
    if secrecy and money: score += 20
    if personal and link: score += 25
    if urgency and personal: score += 15
    if prize and secrecy: score += 15

    return min(score, 40)

# ── Routes ──────────────────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'Palava Proof API', 'patterns': len(PATTERNS)})

@app.route('/api/check', methods=['POST'])
def check_message():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400

    message = data['message'].strip()
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    msg_lower = message.lower()
    confidence = 0
    warnings = []
    scam_types = {}
    tips = []

    # 1. Pattern matching
    for pattern, weight, scam_type, tip in PATTERNS:
        if re.search(pattern, msg_lower, re.IGNORECASE):
            confidence += weight
            label = SCAM_LABELS.get(scam_type, scam_type)
            if label not in warnings:
                warnings.append(label)
            scam_types[scam_type] = scam_types.get(scam_type, 0) + weight
            if tip not in tips:
                tips.append(tip)

    # 2. Semantic combination boost
    confidence += semantic_boost(msg_lower)

    # 3. Phone blacklist check
    phone_score, phone_flags = check_phone_blacklist(message)
    confidence += phone_score
    warnings.extend(phone_flags)

    # 4. URL analysis
    urls = re.findall(r'https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+', message)
    for url in urls:
        url_score, url_flags = analyze_url(url)
        confidence += url_score
        warnings.extend(url_flags)

    confidence = min(confidence, 100)
    dominant_type = max(scam_types, key=scam_types.get) if scam_types else None

    return jsonify({
        'is_scam': confidence >= 30,
        'confidence': confidence,
        'scam_type': SCAM_LABELS.get(dominant_type) if dominant_type else None,
        'warnings': list(dict.fromkeys(warnings)),
        'tips': tips[:3],
        'urls_checked': len(urls),
    })

@app.route('/api/report', methods=['POST'])
def report_scam():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400

    phone = (data.get('phone') or data.get('phone_number') or '').strip()
    url = (data.get('url') or '').strip()
    scam_type = data.get('scam_type') or data.get('type', 'unknown')
    message = data.get('message', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Save report
    c.execute('INSERT INTO reports (message, phone, url, scam_type, reported_at) VALUES (?, ?, ?, ?, ?)',
              (message, phone, url, scam_type, datetime.utcnow().isoformat()))

    # Update phone blacklist
    if phone and re.match(r'\+?[0-9]{7,15}', phone):
        c.execute('''INSERT INTO phone_blacklist (phone, scam_type, last_reported)
                     VALUES (?, ?, ?)
                     ON CONFLICT(phone) DO UPDATE SET
                     times_reported = times_reported + 1,
                     last_reported = excluded.last_reported''',
                  (phone, scam_type, datetime.utcnow().isoformat()))

    # Update URL blacklist
    if url:
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            domain = parsed.netloc.lower()
            if domain:
                c.execute('''INSERT INTO url_blacklist (domain, last_reported)
                             VALUES (?, ?)
                             ON CONFLICT(domain) DO UPDATE SET
                             times_reported = times_reported + 1,
                             last_reported = excluded.last_reported''',
                          (domain, datetime.utcnow().isoformat()))
        except Exception:
            pass

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Report submitted. Thank you for protecting the community!'})

@app.route('/api/recent-scams', methods=['GET'])
def recent_scams():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT scam_type, reported_at, message, phone, url FROM reports ORDER BY reported_at DESC LIMIT 10')
    rows = c.fetchall()
    conn.close()
    return jsonify({'scams': [{'scam_type': r[0], 'reported_at': r[1], 'message': r[2], 'phone': r[3], 'url': r[4]} for r in rows]})

@app.route('/api/stats', methods=['GET'])
def stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM reports')
    total_reports = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM phone_blacklist')
    blacklisted_phones = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM url_blacklist')
    blacklisted_urls = c.fetchone()[0]
    conn.close()
    return jsonify({
        'total_reports': total_reports,
        'blacklisted_phones': blacklisted_phones,
        'blacklisted_urls': blacklisted_urls,
        'patterns': len(PATTERNS),
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
