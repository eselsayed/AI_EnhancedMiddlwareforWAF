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
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            query,
            detection,
            status
        ])


@app.before_request
def monitor_traffic():

    # ignore static
    if request.path.startswith('/static'):
        return

    query_params = request.query_string.decode()

    if not query_params:
        return

    decoded_query = urllib.parse.unquote(query_params)

    # sql rule
    sql_pattern = re.compile(
        r"(or\s+1=1|union\s+select|drop\s+table|--|;|')",
        re.IGNORECASE
    )

    if sql_pattern.search(decoded_query):
        log_entry = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'input': decoded_query,
            'detection': "SQL Injection",
            'status': "Blocked"
        }

        logs.insert(0, log_entry)
        log_to_csv(decoded_query, "SQL Injection", "Blocked")

        print(f"[WAF] BLOCKED SQL | {decoded_query}")

        return make_response(
            render_template(
                '403.html',
                type="SQL Injection",
                confidence="100",
                payload=decoded_query
            ),
            403
        )

    # whitelist safe params
    if re.fullmatch(r"[a-zA-Z0-9_\-]+=[0-9]+", decoded_query):
        log_entry = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'input': decoded_query,
            'detection': "Normal",
            'status': "Allowed"
        }

        logs.insert(0, log_entry)
        log_to_csv(decoded_query, "Normal", "Allowed")

        print(f"[WAF] WHITELIST OK | {decoded_query}")
        return

    # regex hint
    dangerous_chars = re.compile(r"['\"<>;()]|--")
    has_dangerous_stuff = bool(dangerous_chars.search(decoded_query))

    # ml prediction
    tfidf_input = vectorizer.transform([decoded_query.lower()])
    probs = model.predict_proba(tfidf_input)[0]

    if has_dangerous_stuff:
        probs[1] += 0.05
        probs[2] += 0.05

    prediction = np.argmax(probs)
    confidence = np.max(probs) * 100

    labels = {0: 'Normal', 1: 'SQL Injection', 2: 'XSS Attack'}
    attack_type_raw = labels[prediction]

    # decision engine
    is_attack = (prediction != 0) and (confidence >= 80.0)

    if is_attack:
        status = "Blocked"
        attack_type = attack_type_raw
    else:
        status = "Allowed"
        attack_type = "Normal"

    # log request
    log_entry = {
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'input': decoded_query,
        'detection': attack_type,
        'status': status
    }

    print(f"[WAF] {status} | {attack_type} | {decoded_query}")

    logs.insert(0, log_entry)
    log_to_csv(decoded_query, attack_type, status)

    # block response
    if is_attack:
        response = make_response(
            render_template(
                '403.html',
                type=attack_type,
                confidence=f"{confidence:.1f}",
                payload=decoded_query
            ),
            403
        )

        response.headers['X-WAF-Warning'] = f"ATTACK_DETECTED: {attack_type}"
        response.headers['X-WAF-Confidence'] = f"{confidence:.1f}"
        return response


@app.route('/')
def dashboard():
    return render_template('dashboard.html', logs=logs)


if __name__ == "__main__":
    app.run(debug=True)