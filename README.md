# AI-Powered Web Application Firewall (WAF)

## Overview
This project presents a smart Security Middleware built with Flask and Machine Learning to detect and mitigate web-based attacks, specifically SQL Injection (SQLi) and Cross-Site Scripting (XSS). The system employs a Hybrid Security Model that combines Machine Learning predictions with Rule-Based Heuristic analysis to ensure maximum protection.

## Technical Stack
* Backend: Python (Flask)
* Machine Learning: Scikit-learn (Random Forest Classifier)
* Vectorization: TF-IDF (Term Frequency-Inverse Document Frequency)
* Pattern Matching: Regular Expressions (Regex)
* Logging: CSV and In-memory data structures

## Security Logic
The monitoring engine (monitor_traffic) evaluates every incoming request using two main layers:

1. AI Detection Layer: Uses a pre-trained Random Forest model to analyze the intent of the payload. It requires a confidence score of 70% or higher to trigger a block.
2. Heuristic Layer: Uses specific regular expressions to catch high-risk signatures such as "OR 1=1", "DROP TABLE", and HTML event handlers.

If either layer identifies a request as malicious, the system logs the attempt and returns a 403 Forbidden response.

## Installation and Execution

1. Install Dependencies:
   pip install flask joblib numpy scikit-learn

2. Project Files:
   * app.py: Core application logic and WAF middleware.
   * model.pkl: Pre-trained security model.
   * vectorizer.pkl: Saved TF-IDF vectorizer.
   * templates/: Contains dashboard.html and 403.html.

3. Run the Server:
   python app.py

## Testing Scenarios

| Attack Type | Payload Example | Expected Result |
| :--- | :--- | :--- |
| Normal Traffic | /?page=2&limit=10 | Allowed |
| SQL Injection | /?user=' OR 1=1 -- | Blocked (403) |
| XSS Attack | /?data=<svg/onload=confirm(1)> | Blocked (403) |

## Monitoring Dashboard
The application includes a real-time monitoring dashboard accessible at the root URL (/). It displays:
* Timestamp of the request.
* Decoded input payload.
* Detection type (Normal, SQL Injection, XSS, or Detected Attack).
* Final status (Allowed or Blocked).

## Evaluation and Future Work
The current system serves as a proof of concept for integrating AI into web security. Future improvements include:
* Performing a comprehensive evaluation using a validation dataset.
* Generating a Confusion Matrix to refine the optimal Confidence Threshold.
* Expanding the training data to include more diverse attack vectors.

## Contributors
* Esraa Ouda (ID: 20596363)
* Hind Hussein (ID: 20596370)
