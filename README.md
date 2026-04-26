# AI-Enhanced Middleware for Web Application Firewall (WAF)

This project is an intelligent security middleware designed to protect Web APIs from common cyberattacks like **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** using Machine Learning. It serves as a proactive defense layer that analyzes incoming traffic in real-time.

## Key Features
* **Intelligent Traffic Monitoring:** Real-time analysis of URI parameters and payloads.
* **Hybrid Detection Logic:** Combines Random Forest predictions with specialized heuristic checks (`has_dangerous_stuff`).
* **Confidence Thresholding:** Implements an **80% confidence requirement** to reduce False Positives. If the model's certainty is below 80%, the request is treated as 'Normal'.
* **Automated Mitigation:** Immediately blocks detected threats with a "Blocked" status and logs the incident.
* **Comprehensive Logging:** Captures timestamps, attack types, confidence scores, and status for every request.

## Tech Stack
* **Language:** Python
* **Core Libraries:** Scikit-learn (Random Forest), NumPy (Probability Analysis), Pandas.
* **Security Logic:** Custom Normalization and Feature Extraction.
* **Development Environment:** VS Code with Git integration.

## Project Structure (Based on Workspace)
```text
├── app.py                     # Main middleware logic (traffic monitor)
├── step1_preprocess.py        # Data cleaning and normalization
├── step2_train.py             # Model training script
├── step3_evaluate.py          # Performance testing and metrics
├── model.pkl                  # Trained Random Forest model
├── vectorizer.pkl             # TF-IDF Vectorizer for feature extraction
├── waf_logs.csv               # Real-time incident logs
└── static/visuals             # Confusion matrix and accuracy plots
