"""SecuriX Real Target Application - Multi-Vulnerability SAST Benchmark.

Contains real-world security vulnerabilities mapped to OWASP Top 10, CWE, and Indian Regulatory Frameworks (RBI/DPDP/SEBI).
"""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
import requests

# ── 1. Hardcoded Cryptographic Secrets (CWE-798 / RBI-CSF-SEC-4.1) ───────────
JWT_SIGNING_SECRET = "super_secret_production_key_2026_securix"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ── 2. SQL Injection (CWE-89 / OWASP A03 / RBI-CSF-APP-2) ───────────────────
def get_user_account(account_id: str):
    conn = sqlite3.connect("securix_banking.db")
    cursor = conn.cursor()
    # Vulnerable: string formatting directly into SQL query
    query = f"SELECT account_num, balance, aadhaar_num FROM accounts WHERE id = '{account_id}'"
    cursor.execute(query)
    return cursor.fetchall()

# ── 3. Unsafe Deserialization (CWE-502 / ISO27001 A.8.8) ────────────────────
def restore_user_session(cookie_payload: str):
    # Vulnerable: arbitrary code execution via untrusted pickle payload
    data = base64.b64decode(cookie_payload)
    return pickle.loads(data)

# ── 4. Command Injection (CWE-78 / NIST-PR.DS-1) ─────────────────────────────
def run_diagnostic_ping(hostname: str):
    # Vulnerable: shell=True with user concatenation
    cmd = f"ping -c 1 {hostname}"
    return subprocess.check_output(cmd, shell=True)

# ── 5. Server-Side Request Forgery / SSRF (CWE-918 / SEBI-CSCRF-APP-1) ──────
def fetch_partner_webhook(webhook_url: str):
    # Vulnerable: unvalidated internal network traversal (e.g. http://169.254.169.254/latest/meta-data/)
    return requests.get(webhook_url, timeout=5, verify=False)

# ── 6. Insecure Password Hashing (CWE-327 / RBI-CSF-SEC-2) ──────────────────
def hash_admin_password(password: str):
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    user_input = input("Enter expression: ")
    result = eval(user_input)  # nosec
    print("Result:", result)
