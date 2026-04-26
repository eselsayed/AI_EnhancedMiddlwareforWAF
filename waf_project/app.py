from flask import Flask, render_template, request, make_response
import joblib
import numpy as np
import urllib.parse
import csv
import re
from datetime import datetime

app = Flask(__name__)

model = joblib.load('model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

logs = []

def log_to_csv(query, detection, status):
    with open('waf_logs.csv', mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), query, detection, status])

@app.before_request
def monitor_traffic():
    if request.path.startswith('/static') or request.path == '/':
        return

    query_params = str(request.query_string.decode())
    
    if query_params:
        decoded_query = urllib.parse.unquote(query_params)
        
        dangerous_chars = re.compile(r"['\"<>;()]|--")
        has_dangerous_stuff = bool(dangerous_chars.search(decoded_query))

        tfidf_input = vectorizer.transform([decoded_query.lower()])
        probs = model.predict_proba(tfidf_input)[0]
        prediction = np.argmax(probs)
        confidence = np.max(probs) * 100
        
        labels = {0: 'Normal', 1: 'SQL Injection', 2: 'XSS Attack'}
        attack_type = labels[prediction]

        if prediction != 0:
            if confidence < 80.0 or not has_dangerous_stuff:
                prediction = 0
                attack_type = 'Normal'
        
        status = "Blocked" if prediction != 0 else "Allowed"
        
        log_entry = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'input': decoded_query,
            'detection': attack_type,
            'status': status
        }
        logs.insert(0, log_entry)
        log_to_csv(decoded_query, attack_type, status)
        
        if prediction != 0:
            response = make_response(render_template('403.html', 
                                                   type=attack_type, 
                                                   confidence=f"{confidence:.1f}", 
                                                   payload=decoded_query), 403)
            response.headers['X-WAF-Warning'] = f"ATTACK_DETECTED: {attack_type}"
            response.headers['X-WAF-Confidence'] = f"{confidence:.1f}"
            return response

@app.route('/')
def dashboard():
    return render_template('dashboard.html', logs=logs)

if __name__ == "__main__":
    app.run(debug=True)