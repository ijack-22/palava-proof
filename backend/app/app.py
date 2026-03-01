import os
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from datetime import datetime

app = Flask(__name__)

allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
CORS(app, origins=allowed_origins)

DB_PATH = os.path.join(os.path.dirname(__file__), 'palava_proof.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        phone TEXT,
        scam_type TEXT,
        reported_at TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

PATTERNS = [
    (r'send.*pin|share.*pin|pin.*momo|momo.*pin', 30, 'mobile_money', 'Never share your PIN with anyone — not even MTN or Lonestar staff.'),
    (r'mtn.*momo|momo.*transfer|lonestar.*cash|orange.*money', 20, 'mobile_money', 'Verify all mobile money requests by calling the sender directly.'),
    (r'reverse.*transaction|wrong.*transfer.*send back|mistaken.*transfer', 25, 'mobile_money', 'Legitimate wrong transfers are reversed by the network, not by you sending money back.'),
    (r'you.*won|winner.*selected|congratulations.*prize|claim.*prize', 25, 'lottery', 'You cannot win a lottery you never entered.'),
    (r'send.*fee.*claim|pay.*tax.*prize|processing.*fee.*win', 30, 'lottery', 'Legitimate prizes never require upfront fees.'),
    (r'secret.*win|tell.*nobody|keep.*confidential.*prize', 20, 'lottery', 'Real prizes are never secret — this is a pressure tactic.'),
    (r'whatsapp.*job|job.*whatsapp|recruiter.*whatsapp', 20, 'job_scam', 'Legitimate employers do not recruit solely via WhatsApp.'),
    (r'work.*home.*earn|earn.*daily.*usd|make.*money.*online.*liberia', 20, 'job_scam', 'Work-from-home schemes promising quick USD earnings are almost always scams.'),
    (r'un.*job|ngo.*hiring|unicef.*recruitment|undp.*vacancy', 25, 'job_scam', 'Verify UN/NGO jobs only at their official websites.'),
    (r'upfront.*fee.*job|pay.*register.*job|training.*fee.*employment', 30, 'job_scam', 'Legitimate employers never ask you to pay to get a job.'),
    (r'account.*suspend|verify.*account.*now|click.*link.*verify', 25, 'phishing', 'Banks and telecoms never ask you to verify via SMS link.'),
    (r'bit\.ly|tinyurl|t\.co\/|short.*link.*urgent', 15, 'phishing', 'Shortened URLs in urgent messages are a major red flag.'),
    (r'mtn-liberia\.com|lonestar-cash\.net|libtelco-verify', 30, 'phishing', 'This appears to be a fake website impersonating a Liberian telecom.'),
    (r'act.*now.*expire|urgent.*respond|limited.*time.*offer', 15, 'phishing', 'Urgency is a classic manipulation tactic — slow down and verify.'),
    (r'\+231.*prize|\+231.*won|231.*lucky', 20, 'lottery', 'Liberian phone numbers used in prize notifications are a common scam pattern.'),
    (r'password.*reset.*link|enter.*otp.*website|otp.*expire', 25, 'phishing', 'Never enter OTPs on websites you reached through a message link.'),
]

SCAM_LABELS = {
    'mobile_money': 'Mobile Money Fraud',
    'lottery': 'Lottery / Prize Scam',
    'job_scam': 'Fake Job Offer',
    'phishing': 'Phishing / Fake Website',
}

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'Palava Proof API'})

@app.route('/api/check', methods=['POST'])
def check_message():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400

    message = data['message'].lower().strip()
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    confidence = 0
    warnings = []
    scam_types = {}
    tips = set()

    for pattern, weight, scam_type, tip in PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            confidence += weight
            warnings.append(SCAM_LABELS.get(scam_type, scam_type))
            scam_types[scam_type] = scam_types.get(scam_type, 0) + weight
            tips.add(tip)

    confidence = min(confidence, 100)
    warnings = list(set(warnings))

    dominant_type = max(scam_types, key=scam_types.get) if scam_types else None

    return jsonify({
        'is_scam': confidence >= 40,
        'confidence': confidence,
        'scam_type': SCAM_LABELS.get(dominant_type, 'Unknown') if dominant_type else None,
        'warnings': warnings,
        'tips': list(tips)[:3],
    })

@app.route('/api/report', methods=['POST'])
def report_scam():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO reports (message, phone, scam_type, reported_at) VALUES (?, ?, ?, ?)',
              (data.get('message', ''), data.get('phone', ''), data.get('scam_type', ''), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Report submitted. Thank you for protecting the community!'})

@app.route('/api/recent-scams', methods=['GET'])
def recent_scams():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT scam_type, reported_at FROM reports ORDER BY reported_at DESC LIMIT 10')
    rows = c.fetchall()
    conn.close()

    return jsonify({'scams': [{'scam_type': r[0], 'reported_at': r[1]} for r in rows]})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
