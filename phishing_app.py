import socket
from flask import Flask, request, render_template, redirect, jsonify, session
import joblib
import re
import urllib.parse
from datetime import datetime
import whois
import sqlite3  # Or use any other database like MongoDB


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessary for using session

# Database connection function
def connect_db():
    conn = sqlite3.connect('phishing_feedback.db')  # SQLite for simplicity
    return conn

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

# Load the pre-trained model
model = joblib.load('phishing_detection_model.pkl')

# Define the feature extraction function
def extract_features(url):
    features = []
    reasons = []

    # Having IP address
    ip_address_pattern = re.compile(r'http[s]?://(\d{1,3}\.){3}\d{1,3}')
    if ip_address_pattern.match(url):
        features.append(1)
        reasons.append("URL contains an IP address.")
    else:
        features.append(0)

    # URL length
    features.append(len(url))

    # Shortening service
    shortening_services = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
    if any(service in url for service in shortening_services):
        features.append(1)
        reasons.append("URL uses a shortening service.")
    else:
        features.append(0)

    # Having '@' symbol
    if '@' in url:
        features.append(1)
        reasons.append("URL contains '@' symbol.")
    else:
        features.append(0)

    # Double slash redirecting
    if url.count('//') > 1:
        features.append(1)
        reasons.append("URL contains multiple '//'.")
    else:
        features.append(0)

    # Prefix-Suffix in domain
    domain = urllib.parse.urlparse(url).netloc
    if '-' in domain:
        features.append(1)
        reasons.append("Domain contains hyphens ('-').")
    else:
        features.append(0)

    # Having Sub Domain
    if len(domain.split('.')) > 2:
        features.append(1)
        reasons.append("Domain has multiple subdomains.")
    else:
        features.append(0)

    # SSL Final State
    try:
        if re.match(r'^https', url):
            features.append(1)
        else:
            features.append(0)
    except:
        features.append(0)

    # Domain Registration Length
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        registration_length = (expiration_date - datetime.now()).days
        if registration_length <= 365:
            features.append(1)
            reasons.append("Domain registration length is less than a year.")
        else:
            features.append(0)
    except:
        features.append(0)

    # Favicon
    features.append(0)

    # Port
    try:
        port = urllib.parse.urlparse(url).port
        if port not in [80, 443]:
            features.append(1)
            reasons.append("Non-standard port detected.")
        else:
            features.append(0)
    except:
        features.append(0)

    # HTTPS token in URL
    if 'https' in url:
        features.append(1)
    else:
        features.append(0)

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

    # Redirect
    if url.count('//') > 1:
        features.append(1)
        reasons.append("URL contains multiple redirects.")
    else:
        features.append(0)

    # Submitting to email
    if 'mailto:' in url:
        features.append(1)
        reasons.append("URL attempts to submit to email.")
    else:
        features.append(0)

    # Age of Domain
    try:
        creation_date = domain_info.creation_date
        age_of_domain = (datetime.now() - creation_date).days
        if age_of_domain < 180:
            features.append(1)
            reasons.append("Domain age is less than 6 months.")
        else:
            features.append(0)
    except:
        features.append(1)
        reasons.append("Unable to determine the domain age.")

    # DNS Record
    try:
        if whois.whois(domain).domain_name:
            features.append(0)
        else:
            features.append(1)
            reasons.append("DNS record not found.")
    except:
        features.append(1)
        reasons.append("DNS record not found.")

    # Ensure the length of features matches the model's expectation
    features.extend([0] * (30 - len(features)))

    return features, reasons

@app.route('/')
def home():
    session.clear()  # Clear session data to clear history
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']

    # Feature extraction from URL
    features, reasons = extract_features(url)

    # Make prediction
    prediction = model.predict([features])[0]

    # Determine response based on prediction
    if prediction == 1:
        # Not a phishing site
        result = "Not phishing"
        reasons = ["The URL does not exhibit typical phishing characteristics."]
        block_option = False
    elif prediction == 0:
        # Phishing site
        result = "Phishing"
        block_option = True
    else:
        result = "Suspicious but not confirmed as phishing"
        block_option = False

    # Save the current URL and result in session for history
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

@app.route('/block', methods=['POST'])
def block():
    url = session.get('url')
    if url:
        # Implement the logic to block the site.
        # This could involve adding the URL to a blocked list, modifying a firewall, etc.
        blocked = True
        # Example: Add the URL to a simple blocked list
        with open('blocked_sites.txt', 'a') as f:
            f.write(url + '\n')
    else:
        blocked = False

    return jsonify({'blocked': blocked})
@app.route('/initdb')
def initdb():
    init_db()
    return 'Database Initialized'

# API route to handle feedback submission
@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    print(data)  # Debugging step
    url = data['url']
    feedback = data['feedback']
    reason = data['reason']

    # Rest of the code


    # Connect to the database
    conn = connect_db()
    cursor = conn.cursor()

    # Check if URL already exists in the database
    cursor.execute("SELECT * FROM feedback WHERE url = ?", (url,))
    result = cursor.fetchone()

    if result:
        # If feedback already exists, update the counts based on new feedback
        if feedback == "safe":
            cursor.execute("UPDATE feedback SET safe_votes = safe_votes + 1 WHERE url = ?", (url,))
        else:
            cursor.execute("UPDATE feedback SET suspicious_votes = suspicious_votes + 1 WHERE url = ?", (url,))
    else:
        # Insert new feedback into the database
        if feedback == "safe":
            cursor.execute("INSERT INTO feedback (url, safe_votes, suspicious_votes, reason) VALUES (?, 1, 0, ?)", (url, reason))
        else:
            cursor.execute("INSERT INTO feedback (url, safe_votes, suspicious_votes, reason) VALUES (?, 0, 1, ?)", (url, reason))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "Feedback submitted successfully."})

@app.route('/feedback/<url>', methods=['GET'])
def get_feedback(url):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT safe_votes, suspicious_votes, reason FROM feedback WHERE url = ?", (url,))
    result = cursor.fetchone()

    if result:
        return jsonify({
            "safe_votes": result[0],
            "suspicious_votes": result[1],
            "reason": result[2],
        })
    else:
        return jsonify({"message": "No feedback found for this URL."})


if __name__ == '__main__':
    app.run(debug=True)