# AI-Enhanced Middleware WAF (Web Application Firewall)

## Overview

This project is a web application firewall that uses machine learning and rule-based techniques to find dangerous HTTP requests examples being SQL Injection and XSS threats.

The system combines:

* A trained machine learning model (TF-IDF + classifier)
* Regex-based security rules
* Real-time request monitoring using Flask middleware

All incoming requests are analyzed and logged, and results are displayed on a live dashboard.

---

## Features

* Real-time HTTP request inspection
* Detection of SQL Injection and XSS attacks
* Classification of normal and malicious traffic
* Hybrid detection approach (rules + machine learning)
* Confidence threshold control (default: 80%)
* Logging to CSV file
* Web dashboard for monitoring traffic
* Custom 403 response page for blocked requests

---

## Project Structure

```

AI_EnhancedMiddlwareforWAF/
│
├── waf_project/
│   ├── app.py                  # Flask WAF middleware
│   ├── model.pkl               # Trained ML model
│   ├── vectorizer.pkl         # TF-IDF vectorizer
│   ├── waf_logs.csv           # Request logs
│   ├── templates/
│   │   ├── dashboard.html     # Monitoring dashboard
│   │   └── 403.html           # Block page
│   ├── step1_preprocess.py    # Data preprocessing
│   ├── step2_train.py         # Model training
│   ├── step3_evaluate.py      # Model evaluation
│   └── simulate_attack.py     # Test requests
│
├── requirements.txt
└── README.md

````

---

## How It Works

1. Each incoming request is intercepted using Flask middleware
2. The query string is extracted and decoded
3. Two detection layers are applied:
   * Rule-based detection using regex patterns
   * Machine learning classification using a trained model
4. A final decision is made based on prediction and confidence threshold
5. Requests are either:
   * Allowed and logged
   * Blocked and redirected to a 403 page

---

## Detection Logic

* Normal requests are allowed
* Requests classified as attacks with high confidence are blocked
* Low confidence predictions are treated as normal traffic
* Regex rules can immediately flag obvious malicious patterns

---

## Installation

```bash
pip install -r requirements.txt
````

---

## Run the Project

```bash
cd waf_project
python app.py
```

Open in browser:

```
http://127.0.0.1:5000/
```

---

## Testing Examples

### Normal Requests

```
http://127.0.0.1:5000/?name=hello
http://127.0.0.1:5000/?id=123
http://127.0.0.1:5000/?user=ahmed
```

Expected result:

* Status: Allowed
* Detection: Normal

---

### SQL Injection Tests

```
http://127.0.0.1:5000/?id=1' OR '1'='1
http://127.0.0.1:5000/?user=admin'--
http://127.0.0.1:5000/?q=1 OR 1=1
http://127.0.0.1:5000/?login=admin'#
```

Expected result:

* Detection: SQL Injection
* Status: Blocked
* Response: 403 page

---

### XSS Tests

```
http://127.0.0.1:5000/?q=<script>alert(1)</script>
http://127.0.0.1:5000/?input=<img src=x onerror=alert(1)>
http://127.0.0.1:5000/?data=<svg onload=alert(1)>
```

Expected result:

* Detection: XSS Attack
* Status: Blocked
* Response: 403 page

---

### Mixed Attacks

```
http://127.0.0.1:5000/?search=' OR 1=1-- <script>alert(1)</script>
http://127.0.0.1:5000/?q=admin' OR 'a'='a'<script>
```

Expected result:

* Classified as attack
* Blocked or detected depending on model confidence

---

## Notes

* This project is for educational and research purposes
* Not intended for production use
* Accuracy depends on training dataset quality
* Confidence threshold can be adjusted for tuning performance

---

## Contributors

* Esraa Ouda
* Hind Hussein
