"""
Complex Web Microservice - Simulated A/D CTF Service
Includes multiple modern web vulnerabilities across database, session, shell execution, and templates.
"""

import os
import base64
import pickle
import subprocess
import requests
from flask import Flask, request, jsonify, render_template_string
import sqlite3

app = Flask(__name__)

# [Lỗ hổng 1]: Hardcoded Secret Key (CWE-798)
JWT_SECRET = "iboh_super_secret_master_token_2026_xyz"
API_KEY = "FAKE_hardcoded_api_key_for_vulncheck_demo"

def get_db():
    conn = sqlite3.connect("service.db")
    return conn

@app.route("/api/v1/user/search", methods=["GET"])
def search_user():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.cursor()
    
    # [Lỗ hổng 2]: SQL Injection qua f-string (CWE-89)
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify({"results": rows})

@app.route("/api/v1/session/restore", methods=["POST"])
def restore_session():
    cookie_token = request.cookies.get("session_data")
    if not cookie_token:
        return jsonify({"error": "No session cookie"}), 400
    
    raw_payload = base64.b64decode(cookie_token)
    # [Lỗ hổng 3]: Insecure Deserialization (CWE-502) qua pickle.loads
    user_session = pickle.loads(raw_payload)
    return jsonify({"status": "restored", "user": user_session.get("name")})

@app.route("/api/v1/tools/ping", methods=["POST"])
def network_diagnostics():
    host = request.json.get("target_host", "127.0.0.1")
    # [Lỗ hổng 4]: Command Injection qua subprocess với shell=True (CWE-78)
    cmd = f"ping -c 1 {host}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()
    return jsonify({"output": stdout.decode("utf-8", errors="ignore")})

@app.route("/api/v1/webhook/fetch", methods=["GET"])
def trigger_webhook():
    callback_url = request.args.get("url", "")
    # [Lỗ hổng 5]: Server-Side Request Forgery - SSRF (CWE-918)
    resp = requests.get(callback_url, timeout=3)
    return jsonify({"status": resp.status_code, "body": resp.text[:100]})

@app.route("/api/v1/preview", methods=["POST"])
def preview_email():
    template_data = request.json.get("custom_template", "Hello {{name}}")
    # [Lỗ hổng 6]: Server-Side Template Injection - SSTI (CWE-1336)
    rendered = render_template_string(template_data, name="VIP User")
    return rendered

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
