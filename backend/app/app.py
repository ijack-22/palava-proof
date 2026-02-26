from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import re
import hashlib
from datetime import datetime
import requests
import os

app = Flask(__name__)
CORS(app)
app = Flask(__name__)
CORS(app, origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://192.168.1.145:8000"])

# Add this root route
@app.route('/')
def home():
    return jsonify({
        "message": "🛡️ Palava Proof API is running!",
        "endpoints": {
            "check": "/api/check (POST)",
            "report": "/api/report (POST)",
            "recent-scams": "/api/recent-scams (GET)"
        },
        "status": "online"
    })
# Database setup
DATABASE = 'palava_proof.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                type TEXT,
                phone_number TEXT,
                url TEXT,
                reported_by TEXT,
                reported_at TIMESTAMP,
                verified INTEGER DEFAULT 0,
                times_reported INTEGER DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scam_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL,
                description TEXT,
                severity INTEGER DEFAULT 5
            )
        ''')
        
        db.commit()

# Initialize database on startup
init_db()

# Known scam patterns (will be expanded)
SCAM_KEYWORDS = [
    r'won.*prize',
    r'lottery',
    r'free.*data',
    r'free.*airtime',
    r'claim.*reward',
    r'click.*link.*win',
    r'verify.*account.*details',
    r'update.*orange.*money',
    r'your.*account.*locked',
]

@app.route('/api/check', methods=['POST'])
def check_message():
    data = request.json
    message = data.get('message', '')
    
    result = {
        'is_scam': False,
        'confidence': 0,
        'warnings': [],
        'similar_scams': []
    }
    
    # Check against known patterns
    for pattern in SCAM_KEYWORDS:
        if re.search(pattern, message, re.IGNORECASE):
            result['is_scam'] = True
            result['confidence'] += 20
            result['warnings'].append(f"Message contains suspicious phrase: '{pattern}'")
    
    # Check for URLs
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', message)
    for url in urls:
        # Check against known phishing URLs
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        # Query local database for reported scam URLs
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM scams WHERE url = ?', (url,))
        result_count = cursor.fetchone()
        
        if result_count and result_count['count'] > 0:
            result['is_scam'] = True
            result['confidence'] += 30
            result['warnings'].append(f"This URL has been reported as a scam {result_count['count']} times")
        
        # Check URL shortening services
        if any(domain in url for domain in ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly']):
            result['warnings'].append("This uses a link shortener - be careful where it really goes")
    
    # Check for phone numbers
    phones = re.findall(r'0\d{9}|\+231\d{9}', message)
    for phone in phones:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM scams WHERE phone_number = ?', (phone,))
        result_count = cursor.fetchone()
        
        if result_count and result_count['count'] > 0:
            result['is_scam'] = True
            result['confidence'] += 25
            result['warnings'].append(f"This phone number has been reported as a scam {result_count['count']} times")
    
    # Cap confidence at 100
    result['confidence'] = min(result['confidence'], 100)
    
    return jsonify(result)

@app.route('/api/report', methods=['POST'])
def report_scam():
    data = request.json
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if similar scam already exists
    content_hash = hashlib.md5(data.get('content', '').encode()).hexdigest()
    
    cursor.execute('''
        SELECT id, times_reported FROM scams 
        WHERE content LIKE ? OR phone_number = ? OR url = ?
    ''', (f'%{data.get("content", "")[:50]}%', data.get('phone_number'), data.get('url')))
    
    existing = cursor.fetchone()
    
    if existing:
        # Increment report count
        cursor.execute('UPDATE scams SET times_reported = times_reported + 1 WHERE id = ?', (existing['id'],))
        message = "Thank you! This scam has been reported before. Your report helps confirm it."
    else:
        # Insert new scam report
        cursor.execute('''
            INSERT INTO scams (content, type, phone_number, url, reported_at, times_reported)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (
            data.get('content'),
            data.get('type', 'sms'),
            data.get('phone_number'),
            data.get('url'),
            datetime.now()
        ))
        message = "Thank you for reporting! Your report helps protect other Liberians."
    
    db.commit()
    
    return jsonify({'status': 'success', 'message': message})

@app.route('/api/recent-scams', methods=['GET'])
def recent_scams():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM scams 
        WHERE verified = 1 OR times_reported > 3 
        ORDER BY reported_at DESC LIMIT 20
    ''')
    
    scams = cursor.fetchall()
    return jsonify([dict(scam) for scam in scams])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
