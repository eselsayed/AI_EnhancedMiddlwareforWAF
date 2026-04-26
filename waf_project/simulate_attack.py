import requests
import tkinter as tk
from tkinter import messagebox
import time
import urllib.parse

root = tk.Tk()
root.withdraw()

TARGET_URL = "http://127.0.0.1:5000/api"

payloads = [
    # --- Normal Traffic ---
    {"name": "Standard Search", "data": "q=machine+learning+tutorial"},
    {"name": "Profile View", "data": "user_id=550&mode=full"},
    
    # --- SQL Injection (Standard & Obfuscated) ---
    {"name": "Classic SQLi", "data": "id=1' OR '1'='1"},
    {"name": "SQLi Union Select", "data": "id=1 UNION SELECT user, password FROM users--"},
    {"name": "Encoded SQLi", "data": "query=" + urllib.parse.quote("admin' --")},
    
    # --- Cross-Site Scripting (XSS) ---
    {"name": "Basic XSS", "data": "name=<script>alert('XSS')</script>"},
    {"name": "XSS Image Tag", "data": "bio=<img src=x onerror=confirm(1)>"},
    {"name": "Hex Encoded XSS", "data": "input=%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e"},
    
    # --- Advanced Evasion (Tests your Step 1 Normalization) ---
    {"name": "Double URL Encoding", "data": "id=%2527%2520OR%25201%253D1"},
    {"name": "Mixed Case Bypass", "data": "cmd=<sCrIpT>prompt(8)</ScRiPt>"}
]

def trigger_alert(attack_type, confidence, payload):
    msg = f"Security Incident Detected!\n\nType: {attack_type}\nConfidence: {confidence}%\n\nPayload: {payload}\n\nAction: Blocked and Logged."
    messagebox.showwarning("WAF Real-time Protection", msg)

print(f"Starting Simulation on {TARGET_URL}...")
print("-" * 60)

for attack in payloads:
    full_url = f"{TARGET_URL}?{attack['data']}"
    try:
        response = requests.get(full_url, timeout=5)
        
        if response.status_code == 403:
            attack_info = response.headers.get('X-WAF-Warning', 'Unknown Attack')
            conf_info = response.headers.get('X-WAF-Confidence', 'N/A')
            print(f"[BLOCKED] {attack['name']} -> {attack_info} ({conf_info}%)")
            trigger_alert(attack_info, conf_info, attack['data'])
        else:
            print(f"[ALLOWED] {attack['name']}")
            
        time.sleep(0.8)
    except Exception as e:
        print(f"Error: {e}")
        break

print("-" * 60)
print("Simulation Finished.")
root.destroy()