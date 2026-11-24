from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session, abort
from datetime import datetime, timezone, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import subprocess
import hashlib
import time
import uuid
import re

# --- ENVIRONMENT & SECRETS CONFIGURATION ---
ENV_FILE = "/etc/sourceless-dashboard.env"

def load_env(filepath):
    """Parses key-value pairs from environment file."""
    env_vars = {}
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, val = line.split('=', 1)
                    env_vars[key.strip()] = val.strip().strip('"').strip("'")
    return env_vars

env_data = load_env(ENV_FILE)

app = Flask(__name__)

# Fallback configuration values if environment file is missing
app.secret_key = env_data.get("DASHBOARD_SECRET_KEY", "fallback_secret_key_sourceless_2026")
ADMIN_USER = env_data.get("DASHBOARD_ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = generate_password_hash(env_data.get("DASHBOARD_ADMIN_PASS", "Sourceless2026!"))
LOGIN_GATE_ROUTE = env_data.get("LOGIN_GATE_ROUTE", "/auth-console-gate")
CLIENT_SECRET = env_data.get("DASHBOARD_CLIENT_SECRET", "SourcelessClientAuth2026SecretKey!")

# Security Cookie Settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Directory & File Paths
CA_DIR = "/opt/sourceless-dashboard/certs"
CA_KEY = f"{CA_DIR}/ca.key"
CA_CRT = f"{CA_DIR}/ca.crt"
DB_FILE = "/opt/sourceless-dashboard/db_clienti.json"

os.makedirs(CA_DIR, exist_ok=True)

# --- HWID VALIDATION REGEX ---
# Accepts alphanumeric strings and hyphens (length 16 to 64)
HWID_REGEX = re.compile(r'^[a-zA-Z0-9\-]{16,64}$')

def is_valid_hwid(hwid):
    """Validates HWID against safe structural format."""
    return bool(hwid and isinstance(hwid, str) and HWID_REGEX.match(hwid))

def get_client_ip():
    """Extracts real client IP address, including headers passed by Cloudflare Tunnel proxies."""
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr

# --- RATE LIMITING / BRUTE-FORCE PROTECTION ---
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 900  # 15 minutes lockout

def is_ip_blocked(ip):
    """Checks if client IP is currently rate-limited."""
    now = time.time()
    if ip in FAILED_ATTEMPTS:
        data = FAILED_ATTEMPTS[ip]
        if data.get("blocked_until", 0) > now:
            return True
        elif data.get("blocked_until", 0) <= now and data.get("attempts", 0) >= MAX_ATTEMPTS:
            FAILED_ATTEMPTS.pop(ip, None)
    return False

def record_failed_attempt(ip):
    """Increments failure count and triggers lockout if threshold is reached."""
    now = time.time()
    if ip not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[ip] = {"attempts": 1, "blocked_until": 0}
    else:
        FAILED_ATTEMPTS[ip]["attempts"] += 1
        if FAILED_ATTEMPTS[ip]["attempts"] >= MAX_ATTEMPTS:
            FAILED_ATTEMPTS[ip]["blocked_until"] = now + LOCKOUT_TIME_SECONDS

def reset_failed_attempts(ip):
    """Clears failure count on successful login."""
    FAILED_ATTEMPTS.pop(ip, None)

# --- TIME & DATABASE HELPERS ---
def get_local_time():
    """Returns formatted timestamp for Europe/Bucharest timezone."""
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Europe/Bucharest")
        return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    except ImportError:
        tz_fallback = timezone(timedelta(hours=3))
        return datetime.now(tz_fallback).strftime("%Y-%m-%d %H:%M:%S")

def get_today_support_key():
    """Generates dynamic daily support key based on current UTC date."""
    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    salt = "SourcelessSecretSalt2026"
    input_str = f"{today_date}-{salt}"
    return hashlib.sha256(input_str.encode('utf-8')).hexdigest()[:8]

def load_db():
    """Loads client database from JSON file."""
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_db():
    """Persists current in-memory client state to JSON file."""
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(db_clienti, f, indent=4)
    except Exception:
        pass

db_clienti = load_db()

# Generate Root CA certificate and key if missing
if not os.path.exists(CA_KEY) or not os.path.exists(CA_CRT):
    subprocess.run(f"openssl genrsa -out {CA_KEY} 4096", shell=True)
    subprocess.run(f"openssl req -x509 -new -nodes -key {CA_KEY} -sha256 -days 3650 -out {CA_CRT} -subj '/CN=Sourceless-Root-CA/O=Sourceless-OS'", shell=True)

# --- DECORATORS & SECURITY HEADERS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(LOGIN_GATE_ROUTE)
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def apply_security_headers(response):
    """Enforces hardening security headers on all HTTP responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- TEMPLATES ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login // Sourceless-OS</title>
<style>
body { font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.login-card { background: #161b22; padding: 40px; border-radius: 12px; border: 1px solid #30363d; width: 100%; max-width: 380px; }
.logo-area { text-align: center; margin-bottom: 30px; }
.logo-area h2 { color: #58a6ff; margin: 0; font-size: 1.8em; }
.form-group { margin-bottom: 20px; }
label { display: block; margin-bottom: 8px; color: #8b949e; }
input { width: 100%; padding: 12px; border: 1px solid #30363d; background-color: #0d1117; color: #c9d1d9; border-radius: 6px; box-sizing: border-box; }
.btn-submit { background-color: #238636; color: white; border: none; width: 100%; padding: 12px; border-radius: 6px; font-weight: bold; cursor: pointer; }
</style>
</head>
<body>
<div class="login-card">
<div class="logo-area"><h2>Sourceless-OS</h2><p>Technical Support Portal</p></div>
{% if error %}<div style="color: #ff7b72; margin-bottom: 20px; text-align: center;">{{ error }}</div>{% endif %}
<form method="POST">
<div class="form-group"><label>Username</label><input type="text" name="username" required></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn-submit">Sign In</button>
</form>
</div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sourceless-OS // Support Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: #090d11; color: #adbac7; padding: 32px 24px; min-height: 100vh; }
.container { max-width: 1440px; margin: 0 auto; }

/* Navbar */
.navbar { display: flex; justify-content: space-between; align-items: center; padding-bottom: 24px; border-bottom: 1px solid #22272e; margin-bottom: 32px; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand h1 { color: #f0f6fc; font-size: 1.4rem; font-weight: 700; tracking: -0.02em; }
.brand-badge { background: rgba(88, 166, 255, 0.1); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.2); font-size: 0.75rem; padding: 2px 8px; border-radius: 12px; font-weight: 600; }

.header-right { display: flex; align-items: center; gap: 16px; }
.key-box { background: #161b22; border: 1px solid #22272e; padding: 8px 16px; border-radius: 8px; font-size: 0.85rem; display: flex; align-items: center; gap: 10px; }
.key-box .label { color: #768390; }
.key-box .val { font-family: 'JetBrains Mono', monospace; color: #58a6ff; font-weight: 600; font-size: 1rem; }
.btn-logout { color: #768390; text-decoration: none; font-size: 0.875rem; font-weight: 500; padding: 8px 14px; border-radius: 6px; transition: all 0.2s; }
.btn-logout:hover { color: #f0f6fc; background: #161b22; }

/* Stats Grid */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; margin-bottom: 32px; }
.stat-card { background: #12171f; border: 1px solid #22272e; border-radius: 12px; padding: 20px; position: relative; overflow: hidden; }
.stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: #444c56; }
.stat-card.secure::before { background: #3fb950; }
.stat-card.alert::before { background: #f85149; }
.stat-card .title { font-size: 0.825rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #768390; margin-bottom: 8px; }
.stat-card .num { font-size: 2rem; font-weight: 700; color: #f0f6fc; }

/* Table Section */
.table-container { background: #12171f; border: 1px solid #22272e; border-radius: 12px; overflow: hidden; box-shadow: 0 8px 24px rgba(0,0,0,0.2); }
table { width: 100%; border-collapse: collapse; text-align: left; }
th { background: #161b22; color: #768390; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; padding: 14px 20px; border-bottom: 1px solid #22272e; }
td { padding: 16px 20px; border-bottom: 1px solid #1c2128; font-size: 0.875rem; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.015); }

/* Badges & Pills */
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }
.badge-dot { width: 6px; height: 6px; border-radius: 50%; }
.badge-secure { background: rgba(63, 185, 80, 0.1); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.25); }
.badge-secure .badge-dot { background: #3fb950; box-shadow: 0 0 8px #3fb950; }
.badge-alert { background: rgba(248, 81, 73, 0.1); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.25); }
.badge-alert .badge-dot { background: #f85149; box-shadow: 0 0 8px #f85149; }
.badge-waiting { background: rgba(210, 153, 34, 0.1); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.25); }
.badge-waiting .badge-dot { background: #d29922; }

.hwid-pill { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #f0f6fc; background: #161b22; padding: 4px 8px; border-radius: 6px; border: 1px solid #22272e; max-width: 220px; display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cred-chip { background: #161b22; border: 1px solid #22272e; padding: 4px 8px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #58a6ff; display: inline-flex; gap: 6px; margin-right: 4px; }

/* Buttons & Action Bar */
.actions-flex { display: flex; align-items: center; gap: 8px; }
.btn { border: none; padding: 7px 14px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: all 0.2s ease; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
.btn-action { background: #238636; color: #ffffff; }
.btn-action:hover { background: #2ea043; }
.btn-reinstate { background: #1f6feb; color: #ffffff; }
.btn-reinstate:hover { background: #388bfd; }
.btn-stop { background: #da3633; color: #ffffff; }
.btn-stop:hover { background: #f85149; }

.btn-icon-delete { background: transparent; color: #768390; border: 1px solid #22272e; padding: 7px 10px; border-radius: 6px; cursor: pointer; transition: all 0.2s; font-size: 0.85rem; }
.btn-icon-delete:hover { color: #f85149; background: rgba(248, 81, 73, 0.1); border-color: rgba(248, 81, 73, 0.3); }
</style>
</head>
<body>
<div class="container">
<div class="navbar">
<div class="brand">
<h1>Sourceless-OS</h1>
<span class="brand-badge">SUPPORT CONSOLE</span>
</div>
<div class="header-right">
<div class="key-box">
<span class="label">Support Key (UTC):</span>
<span class="val">{{ support_key }}</span>
</div>
<a href="/logout" class="btn-logout">Logout</a>
</div>
</div>

<div class="stats-grid">
<div class="stat-card">
<div class="title">Registered Devices</div>
<div class="num" id="stat-total">0</div>
</div>
<div class="stat-card secure">
<div class="title">Secure Systems</div>
<div class="num" id="stat-secure">0</div>
</div>
<div class="stat-card alert">
<div class="title">Voided Warranties</div>
<div class="num" id="stat-compromised">0</div>
</div>
</div>

<div class="table-container">
<table>
<thead>
<tr>
<th>HWID</th>
<th>Hostname</th>
<th>IP Address</th>
<th>Status</th>
<th>Remote Credentials</th>
<th>Actions</th>
<th>Last Sync</th>
</tr>
</thead>
<tbody id="clients-tbody">
<!-- Dynamic via AJAX -->
</tbody>
</table>
</div>
</div>

<script>
const rejectedTimers = {};

// Sanitizes dynamic strings to prevent XSS attacks
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function triggerAction(endpoint, hwid) {
    await fetch(`/${endpoint}/${encodeURIComponent(hwid)}`, { method: 'POST' });
    updateDashboard();
}

async function confirmDelete(hwid) {
    if (confirm(`Are you sure you want to delete the client with HWID:\n${hwid}?`)) {
        await triggerAction('delete_client', hwid);
    }
}

async function updateDashboard() {
    try {
        const res = await fetch('/api/data');
        const data = await res.json();
        
        document.getElementById('stat-total').innerText = data.stats.total;
        document.getElementById('stat-secure').innerText = data.stats.secure;
        document.getElementById('stat-compromised').innerText = data.stats.compromised;
        
        const tbody = document.getElementById('clients-tbody');
        tbody.innerHTML = '';
        
        for (const [hwid, info] of Object.entries(data.clienti)) {
            const tr = document.createElement('tr');

            // Handle auto-reset timeout for rejected support status (10s)
            if (info.support_state === 'rejected') {
               if (!rejectedTimers[hwid]) {
                    rejectedTimers[hwid] = setTimeout(() => {
                        triggerAction('stop_support', hwid);
                        delete rejectedTimers[hwid];
                    }, 10000);
               }
            } else if (rejectedTimers[hwid]) {
                 clearTimeout(rejectedTimers[hwid]);
                 delete rejectedTimers[hwid];
            }
            
            let statusHtml = info.status === 'Integru' 
                ? '<span class="badge badge-secure"><span class="badge-dot"></span>Secure</span>' 
                : '<span class="badge badge-alert"><span class="badge-dot"></span>Modified</span>';
                
            let credsHtml = '<span style="color: #444c56;">—</span>';
            if (info.support_state === 'approved' && info.rustdesk_id && info.rustdesk_id !== 'N/A') {
                credsHtml = `<span class="cred-chip">ID: ${escapeHtml(info.rustdesk_id)}</span><span class="cred-chip">PW: ${escapeHtml(info.rustdesk_pw)}</span>`;
            } else if (info.support_state === 'rejected') {
                credsHtml = `<span class="badge badge-alert">Access Denied</span>`;
            } else if (info.support_state === 'waiting') {
                credsHtml = `<span class="badge badge-waiting"><span class="badge-dot"></span>Waiting Approval</span>`;
            }

            let actionsHtml = '<div class="actions-flex">';
            const safeHwid = escapeHtml(hwid);
            
            if (info.status !== 'Integru') {
                actionsHtml += `<button onclick="triggerAction('reinstate', '${safeHwid}')" class="btn btn-reinstate">Reinstate</button>`;
            }

            if (info.support_state === 'waiting') {
                actionsHtml += `<button onclick="triggerAction('stop_support', '${safeHwid}')" class="btn btn-stop">Cancel Request</button>`;
            } else if (info.support_state === 'approved') {
                actionsHtml += `<button onclick="triggerAction('stop_support', '${safeHwid}')" class="btn btn-stop">Stop Support</button>`;
            } else {
                actionsHtml += `<button onclick="triggerAction('request_support', '${safeHwid}')" class="btn btn-action">Request Access</button>`;
            }

            actionsHtml += `<button onclick="confirmDelete('${safeHwid}')" class="btn-icon-delete" title="Delete Client">🗑️</button>`;
            actionsHtml += '</div>';

            tr.innerHTML = `
                <td><span class="hwid-pill" title="${safeHwid}">${safeHwid}</span></td>
                <td><strong style="color: #f0f6fc;">${escapeHtml(info.hostname)}</strong></td>
                <td><span style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #768390;">${escapeHtml(info.ip)}</span></td>
                <td>${statusHtml}</td>
                <td>${credsHtml}</td>
                <td>${actionsHtml}</td>
                <td><span style="font-size: 0.8rem; color: #768390;">${escapeHtml(info.last_seen)}</span></td>
            `;
            tbody.appendChild(tr);
        }
    } catch (e) {
        console.error("Error updating dashboard:", e);
    }
}

setInterval(updateDashboard, 2000);
updateDashboard();
</script>
</body>
</html>
"""

# --- ROUTES ---
# Standard /login route is disabled (returns 404) to confuse automated scanners
@app.route('/login')
def legacy_login():
    abort(404)

@app.route(LOGIN_GATE_ROUTE, methods=['GET', 'POST'])
def login():
    client_ip = get_client_ip()
    
    if is_ip_blocked(client_ip):
        return render_template_string(LOGIN_TEMPLATE, error="Too many failed attempts. Temporarily locked out."), 429

    error = None
    if request.method == 'POST':
        user_input = request.form.get('username')
        pass_input = request.form.get('password')
        
        if user_input == ADMIN_USER and check_password_hash(ADMIN_PASSWORD_HASH, pass_input):
            reset_failed_attempts(client_ip)
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            record_failed_attempt(client_ip)
            error = "Invalid username or password!"

    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    csr_pem = data.get('csr')
    
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid or missing HWID"}), 400

    device_token = str(uuid.uuid4())
    signed_cert = ""

    # Daca clientul a trimis o cerere CSR, o semnam cu Root CA-ul backend-ului
    if csr_pem and "BEGIN CERTIFICATE REQUEST" in csr_pem:
        try:
            csr_file = f"/tmp/{hwid}.csr"
            crt_file = f"/tmp/{hwid}.crt"
            
            with open(csr_file, "w") as f:
                f.write(csr_pem)

            # Semnare CSR folosind CA-ul local din container
            cmd = f"openssl x509 -req -in {csr_file} -CA {CA_CRT} -CAkey {CA_KEY} -CAcreateserial -out {crt_file} -days 3650 -sha256"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if res.returncode == 0 and os.path.exists(crt_file):
                with open(crt_file, "r") as f:
                    signed_cert = f.read()
                os.remove(crt_file)
                
            if os.path.exists(csr_file):
                os.remove(csr_file)
        except Exception as e:
            pass

    if hwid not in db_clienti:
        db_clienti[hwid] = {
            "status": "Inscris",
            "support_state": "idle",
            "pending_cmd": "none"
        }

    db_clienti[hwid]['token'] = device_token
    save_db()

    return jsonify({
        "status": "registered", 
        "token": device_token,
        "certificate": signed_cert
    })

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(LOGIN_GATE_ROUTE)

@app.route('/')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE, support_key=get_today_support_key())

@app.route('/api/data')
@login_required
def api_data():
    total = len(db_clienti)
    secure = sum(1 for c in db_clienti.values() if c.get('status') == 'Integru')
    compromised = total - secure
    stats = {"total": total, "secure": secure, "compromised": compromised}
    return jsonify({"clienti": db_clienti, "stats": stats})

@app.route('/reinstate/<hwid>', methods=['POST'])
@login_required
def reinstate_client(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    if hwid in db_clienti:
        db_clienti[hwid]['pending_reinstate'] = True
        db_clienti[hwid]['status'] = 'Integru'
        save_db()
    return jsonify({"status": "ok"})

@app.route('/delete_client/<hwid>', methods=['POST'])
@login_required
def delete_client(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    if hwid in db_clienti:
        db_clienti.pop(hwid, None)
        save_db()
        return jsonify({"status": "ok"})
    return jsonify({"error": "Client not found"}), 404

@app.route('/request_support/<hwid>', methods=['POST'])
@login_required
def request_support(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    if hwid in db_clienti:
        db_clienti[hwid]['pending_cmd'] = 'start_support'
        db_clienti[hwid]['support_state'] = 'waiting'
        save_db()
    return jsonify({"status": "ok"})

@app.route('/stop_support/<hwid>', methods=['POST'])
@login_required
def stop_support(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    if hwid in db_clienti:
        db_clienti[hwid]['pending_cmd'] = 'stop_support'
        db_clienti[hwid]['support_state'] = 'idle'
        db_clienti[hwid]['rustdesk_id'] = 'N/A'
        db_clienti[hwid]['rustdesk_pw'] = 'N/A'
        save_db()
    return jsonify({"status": "ok"})

@app.route('/api/client/submit_credentials', methods=['POST'])
def submit_credentials():
    data = request.get_json() or {}
    hwid = data.get('hwid')

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    # Extract dynamic token for this specific HWID from DB
    expected_token = db_clienti.get(hwid, {}).get('token') if hwid else None

    # Validate client token
    if not expected_token or request.headers.get('X-Sourceless-Token') != expected_token:
        return jsonify({"error": "Unauthorized"}), 401

    if hwid in db_clienti:
        current_state = db_clienti[hwid].get('support_state')

        # Override late approvals if administrator canceled support request
        if current_state != 'waiting' and data.get('status') == 'approved':
            db_clienti[hwid]['pending_cmd'] = 'stop_support'
            db_clienti[hwid]['support_state'] = 'idle'
            db_clienti[hwid]['rustdesk_id'] = 'N/A'
            db_clienti[hwid]['rustdesk_pw'] = 'N/A'
        elif data.get('status') == 'approved':
            db_clienti[hwid]['rustdesk_id'] = data.get('rustdesk_id')
            db_clienti[hwid]['rustdesk_pw'] = data.get('rustdesk_pw')
            db_clienti[hwid]['support_state'] = 'approved'
        else:
            db_clienti[hwid]['support_state'] = 'rejected'
            db_clienti[hwid]['rustdesk_id'] = 'Rejected'
            db_clienti[hwid]['rustdesk_pw'] = 'N/A'
        
        save_db()
        return jsonify({"status": "ok"}), 200

    return jsonify({"error": "Client not found"}), 404

@app.route('/api/report', methods=['POST'])
def report_status():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    hostname = data.get('hostname')
    status = data.get('status')
    client_ip = get_client_ip()

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    # 1. Extract saved token from DB for this HWID
    expected_token = db_clienti.get(hwid, {}).get('token') if hwid else None

    # 2. Verify if received token matches expected token
    if not expected_token or request.headers.get('X-Sourceless-Token') != expected_token:
        return jsonify({"error": "Unauthorized"}), 401

    if not hwid or not hostname or not status:
        return jsonify({"error": "Incomplete data."}), 400

    command = "none"
    current_client = db_clienti.get(hwid, {})

    pending_cmd = current_client.get('pending_cmd', '')
    pending_reinstate = current_client.get('pending_reinstate', False)

    if pending_cmd:
        command = pending_cmd
        current_client['pending_cmd'] = ''
    elif pending_reinstate:
        command = "clear_tamper"
        status = "Integru"
        pending_reinstate = False

    # 3. Persist client state (preserve token)
    db_clienti[hwid] = {
        "hostname": hostname,
        "ip": client_ip,
        "status": status,
        "last_seen": get_local_time(),
        "pending_reinstate": pending_reinstate,
        "rustdesk_id": current_client.get('rustdesk_id', 'N/A'),
        "rustdesk_pw": current_client.get('rustdesk_pw', 'N/A'),
        "support_state": current_client.get('support_state', 'idle'),
        "pending_cmd": current_client.get('pending_cmd', ''),
        "token": expected_token  # Preserve token in DB
    }
    save_db()
    return jsonify({"message": "Status received", "command": command}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)