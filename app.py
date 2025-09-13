import os
import random
import time
import re
from datetime import datetime
from threading import Thread
from collections import Counter

import openai
import requests
from flask import Flask, render_template
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# --- Setup ---
app = Flask(__name__)

# --- API Key Configuration ---
try:
    openai.api_key = os.environ["OPENAI_API_KEY"]
    ABUSEIPDB_API_KEY = os.environ["ABUSEIPDB_API_KEY"]
except KeyError as e:
    print(f"🔴 FATAL ERROR: The '{e.args[0]}' environment variable is not set.")
    print("🔴 Please set it before running the application.")
    exit()

# --- AI & ML Model Setup ---

# OpenAI Analysis Function
def analyze_log_entry_with_openai(log_entry: str) -> str:
    system_prompt = (
        "You are a senior cybersecurity analyst. Analyze this web server log. "
        "Identify the threat type (e.g., SQL Injection, XSS, Directory Traversal, Benign). "
        "Provide a one-sentence description. If benign, state 'Normal traffic detected'."
    )
    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": log_entry}
            ],
            temperature=0.1,
            max_tokens=80
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"🔴 OpenAI API Error: {e}")
        return "Error during OpenAI analysis."

# Network Anomaly Detection
# This model now learns from the sample log file's statistical properties
log_lines = open('access.log').readlines()
def parse_log_line(line):
    # Simple regex to extract IP and request details. A more robust regex might be needed for other log formats.
    match = re.match(r'(\S+) \S+ \S+ \[.*?\] "(\S+ .*? \S+)" (\d+) (\d+)', line)
    if match:
        return {
            "ip": match.group(1),
            "request": match.group(2),
            "status_code": int(match.group(3)),
            "response_size": int(match.group(4))
        }
    return None

parsed_logs = [parse_log_line(line) for line in log_lines if parse_log_line(line)]
network_features = [[log['status_code'], log['response_size']] for log in parsed_logs]
isolation_forest = IsolationForest(contamination=0.2, random_state=42)
isolation_forest.fit(network_features)

# Phishing Email Classifier (Unchanged from original)
email_texts = ["Your account has been compromised...", "Meeting agenda", "Urgent: Update your billing", "Lunch plans?", "Congratulations! You won...", "Please review the attached invoice"]
labels = [1, 0, 1, 0, 1, 0]
vectorizer = TfidfVectorizer()
X_train = vectorizer.fit_transform(email_texts)
phishing_clf = LogisticRegression()
phishing_clf.fit(X_train, labels)

def classify_email(text):
    pred = phishing_clf.predict(vectorizer.transform([text]))[0]
    return "Phishing" if pred == 1 else "Legitimate"

# --- Threat Intelligence ---
def get_ip_intel(ip: str) -> dict:
    """Fetches IP reputation from AbuseIPDB."""
    url = f'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()['data']
        return {
            "score": data.get('abuseConfidenceScore', 0),
            "country": data.get('countryCode', 'N/A'),
            "isp": data.get('isp', 'N/A')
        }
    except requests.exceptions.RequestException as e:
        print(f"🟡 AbuseIPDB API Error: {e}")
        return {"score": 0, "country": "Error", "isp": "Error"}

# --- Data Stores ---
alerts = []
responses = []

# --- Simulator & Event Loop ---
def event_loop():
    while True:
        # --- 1. Simulate and Analyze Network Traffic ---
        log_line = random.choice(log_lines)
        parsed_log = parse_log_line(log_line)
        
        if parsed_log:
            features = [[parsed_log['status_code'], parsed_log['response_size']]]
            prediction = isolation_forest.predict(features)
            
            # If ML model flags an anomaly, escalate to OpenAI and get IP Intel
            if prediction[0] == -1:
                openai_analysis = analyze_log_entry_with_openai(parsed_log['request'])
                ip_intel = get_ip_intel(parsed_log['ip'])
                
                # Determine threat level based on both AI analysis and IP reputation
                is_high_threat = "Normal traffic" not in openai_analysis or ip_intel.get('score', 0) > 50
                threat_level = "High" if is_high_threat else "Low"

                alert = {
                    "type": "Network Anomaly",
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": parsed_log['ip'],
                    "description": openai_analysis,
                    "threat_level": threat_level,
                    "raw_log": parsed_log['request'],
                    "intel": ip_intel
                }
                alerts.append(alert)
                automated_response(alert)
        
        # --- 2. Simulate and Analyze Emails (Unchanged) ---
        email_subject = random.choice(email_texts)
        if classify_email(email_subject) == "Phishing":
            alert = {
                "type": "Phishing Email",
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "sender": f"spammer{random.randint(1,100)}@evilcorp.com",
                "subject": email_subject,
                "description": "Potential phishing attempt detected via ML model.",
                "threat_level": "High"
            }
            alerts.append(alert)
            automated_response(alert)

        # Keep the lists from growing indefinitely in a long-running demo
        if len(alerts) > 100:
            alerts.pop(0)
            responses.pop(0)
            
        time.sleep(4)

# --- Automated Response ---
def automated_response(alert):
    action = f"Alert triggered for {alert['type']} from {alert.get('source_ip', alert.get('sender', 'N/A'))}."
    if alert['type'] == 'Network Anomaly' and alert['threat_level'] == 'High':
        # Generate a more realistic, actionable response
        action = f"High-threat IP {alert['source_ip']} detected. Generated firewall rule: iptables -A INPUT -s {alert['source_ip']} -j DROP"
    elif alert['type'] == 'Phishing Email':
        action = f"Phishing email from {alert['sender']} quarantined."
    
    responses.append({"timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "action": action})

# --- Flask Routes ---
@app.route("/")
def dashboard():
    # Calculate data for the chart
    alert_types = [alert['type'] for alert in alerts]
    type_counts = Counter(alert_types)
    chart_data = {
        "labels": list(type_counts.keys()),
        "values": list(type_counts.values())
    }
    return render_template('dashboard.html', alerts=alerts, responses=responses, chart_data=chart_data)

# --- Main Execution ---
if __name__ == "__main__":
    print("🚀 Starting AI Security Dashboard...")
    print("➡️  Make sure your OPENAI_API_KEY and ABUSEIPDB_API_KEY are set.")
    print("➡️  Open your web browser to http://127.0.0.1:5000")
    
    # Start the background event simulation thread
    thread = Thread(target=event_loop, daemon=True)
    thread.start()
    
    # Start the Flask web server
    app.run(debug=False, host='0.0.0.0')