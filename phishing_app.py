
import socket
from flask import Flask, request, render_template, jsonify, session
import joblib
import re
import urllib.parse
from datetime import datetime
import whois
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

BLOCKED_URLS_FILE = r"C:\Users\SANJANA\OneDrive\Desktop\Final Year Project\blocked_sites.txt"
# Load the trained model
model = joblib.load('phishing_detection_model.pkl')

# Connect to SQLite DB
def connect_db():
    return sqlite3.connect('phishing_feedback.db', check_same_thread=False)

# Initialize DB table
def init_db():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            safe_votes INTEGER DEFAULT 0,
            suspicious_votes INTEGER DEFAULT 0,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Feature extraction
def extract_features(raw_url):
    reasons = []
    
    # Add https:// if scheme missing
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    parsed_url = urllib.parse.urlparse(raw_url)
    domain = parsed_url.netloc
    features = []

    # IP address
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    features.append(1 if ip_pattern.match(domain) else 0)
    if ip_pattern.match(domain): reasons.append("URL contains an IP address.")

    # URL length
    features.append(len(raw_url))

    # Shortening service
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
    features.append(1 if any(s in raw_url for s in shorteners) else 0)
    if any(s in raw_url for s in shorteners): reasons.append("URL uses a shortening service.")

    # '@' symbol
    features.append(1 if '@' in raw_url else 0)
    if '@' in raw_url: reasons.append("URL contains '@' symbol.")

    # Redirection '//'
    features.append(1 if raw_url.count('//') > 1 else 0)
    if raw_url.count('//') > 1: reasons.append("URL contains multiple '//'.")
    
    # Hyphens in domain
    features.append(1 if '-' in domain else 0)
    if '-' in domain: reasons.append("Domain contains hyphens.")

    # Subdomains
    features.append(1 if len(domain.split('.')) > 2 else 0)
    if len(domain.split('.')) > 2: reasons.append("Domain has multiple subdomains.")

    # HTTPS
    features.append(0 if raw_url.startswith('https') else 1)
    if not raw_url.startswith('https'): reasons.append("Connection is not secure (no HTTPS).")

    # Domain registration length
    try:
        domain_info = whois.whois(domain)
        reg_length = (domain_info.expiration_date - datetime.now()).days
        features.append(1 if reg_length <= 365 else 0)
        if reg_length <= 365: reasons.append("Domain registration length is less than a year.")
    except:
        features.append(1)
        reasons.append("Unable to determine domain registration length.")

    # Favicon (skipped, placeholder)
    features.append(0)

    # Non-standard port
    try:
        port = parsed_url.port
        if port and port not in [80, 443]:
            features.append(1)
            reasons.append("Non-standard port used.")
        else:
            features.append(0)
    except:
        features.append(0)

    # Https token in URL
    features.append(1 if 'https' in raw_url else 0)

    # Abnormal URL
    try:
        if socket.gethostbyname(domain) != domain:
            features.append(1)
            reasons.append("Abnormal URL detected.")
        else:
            features.append(0)
    except:
        features.append(1)
        reasons.append("Abnormal URL detected.")

    # Redirection again
    features.append(1 if raw_url.count('//') > 1 else 0)

    # mailto in URL
    features.append(1 if 'mailto:' in raw_url else 0)
    if 'mailto:' in raw_url: reasons.append("URL attempts to submit to email.")

    # Domain age
    try:
        age = (datetime.now() - domain_info.creation_date).days
        features.append(1 if age < 180 else 0)
        if age < 180: reasons.append("Domain age is less than 6 months.")
    except:
        features.append(1)
        reasons.append("Unable to determine domain age.")

    # DNS record
    try:
        if domain_info.domain_name:
            features.append(0)
        else:
            features.append(1)
            reasons.append("DNS record not found.")
    except:
        features.append(1)
        reasons.append("DNS record not found.")

    # Final padding
    features.extend([0] * (30 - len(features)))
    return features, reasons

# Routes
@app.route('/')
def home():
    session.clear()
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features, reasons = extract_features(url)
    prediction = model.predict([features])[0]

    if prediction == 0:
        result = "Not phishing"
        reasons = ["The URL does not exhibit typical phishing characteristics."]
        block_option = False
    elif prediction == 1:
        result = "Phishing"
        block_option = True
    else:
        result = "Suspicious"
        block_option = False

    session['url'] = url
    session['result'] = result
    session['reasons'] = reasons
    session['block_option'] = block_option

    return jsonify({
        'result': result,
        'url': url,
        'reasons': reasons,
        'block_option': block_option
    })

# @app.route('/block', methods=['POST'])
# def block():
#     url = session.get('url')
#     if url:
#         with open('blocked_sites.txt', 'a') as f:
#             f.write(url + '\n')
#         return jsonify({'blocked': True})
#     return jsonify({'blocked': False})

# Helper Functions
def read_blocked_urls():
    if not os.path.exists(BLOCKED_URLS_FILE):
        return []
    with open(BLOCKED_URLS_FILE, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def write_blocked_url(url):
    urls = read_blocked_urls()
    if url not in urls:
        with open(BLOCKED_URLS_FILE, 'a') as f:
            f.write(url + '\n')

def clear_blocked_urls():
    open(BLOCKED_URLS_FILE, 'w').close()

# Route to block a URL
@app.route('/block-url', methods=['POST'])
def block_url():
    data = request.get_json()
    url = data.get('url')
    if url:
        write_blocked_url(url)
        return jsonify({'status': 'success', 'message': 'URL blocked'})
    return jsonify({'status': 'error', 'message': 'No URL provided'}), 400

# Route to get all blocked URLs
@app.route('/get-blocked-urls', methods=['GET'])
def get_blocked_urls():
    urls = read_blocked_urls()
    return jsonify({'blocked_urls': urls})

# Route to reset all blocked URLs
# @app.route('/reset-blocked-urls', methods=['POST'])
# def reset_blocked_urls():
#     clear_blocked_urls()
#     return jsonify({'status': 'success', 'message': 'All URLs unblocked'})

@app.route('/initdb')
def initdb():
    init_db()
    return 'Database Initialized'

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    url = data['url']
    feedback = data['feedback']
    reason = data['reason']

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM feedback WHERE url = ?", (url,))
    result = cursor.fetchone()

    if result:
        if feedback == "safe":
            cursor.execute("UPDATE feedback SET safe_votes = safe_votes + 1 WHERE url = ?", (url,))
        else:
            cursor.execute("UPDATE feedback SET suspicious_votes = suspicious_votes + 1 WHERE url = ?", (url,))
    else:
        cursor.execute("INSERT INTO feedback (url, safe_votes, suspicious_votes, reason) VALUES (?, ?, ?, ?)",
                       (url, 1 if feedback == "safe" else 0, 0 if feedback == "safe" else 1, reason))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "Feedback submitted successfully."})

@app.route('/feedback/<url>', methods=['GET'])
def get_feedback(url):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT safe_votes, suspicious_votes, reason FROM feedback WHERE url = ?", (url,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({
            "safe_votes": result[0],
            "suspicious_votes": result[1],
            "reason": result[2],
        })
    else:
        return jsonify({"message": "No feedback found for this URL."})

from flask import redirect

@app.route('/proceed/<path:url>')
def proceed(url):
    # Add scheme if it's missing
    if not url.startswith("http"):
        url = "https://" + url
    return redirect(url)


if __name__ == '__main__':
    app.run(debug=True)

