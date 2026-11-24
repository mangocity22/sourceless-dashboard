from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from datetime import datetime, timezone, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import uuid

# --- ENVIRONMENT & SECRETS CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = "/etc/sourceless-dashboard.env"


def load_env(filepath):
    """Parses key-value pairs from environment file."""
    env_vars = {}
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    env_vars[key.strip()] = val.strip().strip('"').strip("'")
    return env_vars


env_data = load_env(ENV_FILE)


def get_cfg(key, default=None):
    return env_data.get(key) or os.environ.get(key) or default


app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# Secret key comes from environment in production; falls back to an ephemeral runtime key
app.secret_key = get_cfg("DASHBOARD_SECRET_KEY") or secrets.token_hex(32)
ADMIN_USER = get_cfg("DASHBOARD_ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = generate_password_hash(get_cfg("DASHBOARD_ADMIN_PASS", "Sourceless2026!"))
LOGIN_GATE_ROUTE = get_cfg("LOGIN_GATE_ROUTE", "/auth-console-gate")
CLIENT_SECRET = get_cfg("DASHBOARD_CLIENT_SECRET", "SourcelessClientAuth2026SecretKey!")
SUPPORT_KEY_SALT = get_cfg("SUPPORT_KEY_SALT", "SourcelessSecretSalt2026")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Directory & File Paths
DATA_DIR = "/opt/sourceless-dashboard" if os.path.isdir("/opt/sourceless-dashboard") else BASE_DIR
CA_DIR = os.path.join(DATA_DIR, "certs")
CA_KEY = os.path.join(CA_DIR, "ca.key")
CA_CRT = os.path.join(CA_DIR, "ca.crt")
DB_FILE = os.path.join(DATA_DIR, "db_clienti.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.json")
YARA_FILE = os.path.join(DATA_DIR, "yara_alerts.json")

ONLINE_THRESHOLD_SECONDS = 30
MAX_AUDIT_ENTRIES = 150
MAX_YARA_ENTRIES = 100

ALLOWED_REMOTE_CMDS = {
    "check_update",
    "set_channel_stable",
    "set_channel_testing",
    "reboot_device",
}

os.makedirs(CA_DIR, exist_ok=True)
DB_LOCK = threading.RLock()
HWID_REGEX = re.compile(r"^[a-zA-Z0-9\-]{16,64}$")

SOURCELESS_LOGO_SVG = """
<svg viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="slGrad" x1="18.72" y1="127.7" x2="237.97" y2="127.7" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#a7ff52"/>
      <stop offset="1" stop-color="#6051ed"/>
    </linearGradient>
  </defs>
  <path fill="url(#slGrad)" d="M128.35,250.66c-4.04,0-8.08-1.04-11.68-3.12l-86.27-49.81c-7.2-4.16-11.68-11.91-11.68-20.23v-99.61c0-8.32,4.48-16.07,11.68-20.23L116.67,7.86c7.2-4.16,16.15-4.16,23.36,0l86.27,49.81c7.2,4.16,11.68,11.91,11.68,20.23v99.61c0,8.32-4.47,16.07-11.68,20.23l-86.27,49.81c-3.6,2.08-7.64,3.12-11.68,3.12ZM128.35,7.85c-3.5,0-7,.9-10.12,2.7L31.96,60.36c-6.24,3.61-10.12,10.32-10.12,17.53v99.61c0,7.21,3.88,13.93,10.12,17.53l86.27,49.81c6.24,3.6,14,3.61,20.24,0l86.27-49.81c6.24-3.61,10.12-10.32,10.12-17.53v-99.61c0-7.21-3.88-13.93-10.12-17.53L138.47,10.55c-3.12-1.8-6.62-2.7-10.12-2.7ZM130.89,135.33c-1.58.17-2.72,1.6-2.55,3.18.17,1.58,1.6,2.72,3.18,2.55,1.58-.17,2.72-1.6,2.55-3.18s-1.6-2.72-3.18-2.55ZM148.27,147.75c-1.58.17-2.72,1.6-2.55,3.18s1.6,2.72,3.18,2.55c1.58-.17,2.72-1.6,2.55-3.18-.17-1.58-1.6-2.72-3.18-2.55ZM136.11,165.51l-20.02,4.25c-.26.05-.53.09-.79.09-1.78,0-3.39-1.24-3.77-3.07-.43-2.09.89-4.13,2.98-4.57l23.58-4.99c1.83-.38,3.07-2,3.07-3.79,0-.26-.04-.53-.09-.79-.45-2.1-2.5-3.43-4.58-2.98l-23.58,4.99c-2.09.43-4.13-.89-4.58-2.98h0c-.43-2.1.89-4.15,2.98-4.58l9.5-2.02c1.04-.21,1.9-.83,2.43-1.66.6-.91.81-2.07.46-3.22-.58-1.96-2.69-3.04-4.69-2.62l-44.9,9.51,17.51-64.39-29.62-32.92-23.62,86.86,14.03,15.04,15.83,16.99,14.91,15.98,54.57-11.56c1.83-.37,3.07-1.99,3.07-3.77,0-.26-.02-.53-.09-.81-.43-2.09-2.48-3.41-4.58-2.98ZM125.75,120.69c1.58-.17,2.72-1.6,2.55-3.18s-1.6-2.72-3.18-2.55c-1.58.17-2.72,1.6-2.55,3.18.17,1.58,1.6,2.72,3.18,2.55ZM108.31,108.27c1.58-.17,2.72-1.6,2.55-3.18-.17-1.58-1.6-2.72-3.18-2.55-1.58.17-2.72,1.6-2.55,3.18.17,1.58,1.6,2.72,3.18,2.55ZM120.58,89.88l20.02-4.25c.26-.05.53-.09.79-.09,1.78,0,3.39,1.24,3.77,3.07.43,2.09-.89,4.13-2.98,4.57l-23.58,4.99c-1.83.38-3.07,2-3.07,3.79,0,.26.04.53.09.79.45,2.1,2.5,3.43,4.58,2.98l23.58-4.99c2.09-.43,4.13.89,4.58,2.98h0c.43,2.1-.89,4.15-2.98,4.58l-9.5,2.02c-1.04.21-1.9.83-2.43,1.66-.6.91-.81,2.07-.46,3.22.58,1.96,2.69,3.04,4.69,2.62l44.9-9.51-17.51,64.39,29.62,32.92,23.62-86.86-14.03-15.04-15.83-16.99-14.91-15.98-54.57,11.56c-1.83.37-3.07,1.99-3.07,3.77,0,.26.02.53.09.81.43,2.09,2.48,3.41,4.58,2.98Z"/>
</svg>
"""


def is_valid_hwid(hwid):
    return bool(hwid and isinstance(hwid, str) and HWID_REGEX.match(hwid))


def get_client_ip():
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


# --- RATE LIMITING ---
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 900


def is_ip_blocked(ip):
    with DB_LOCK:
        now = time.time()
        if ip in FAILED_ATTEMPTS:
            data = FAILED_ATTEMPTS[ip]
            if data.get("blocked_until", 0) > now:
                return True
            if data.get("blocked_until", 0) <= now and data.get("attempts", 0) >= MAX_ATTEMPTS:
                FAILED_ATTEMPTS.pop(ip, None)
        return False


def record_failed_attempt(ip):
    with DB_LOCK:
        now = time.time()
        if ip not in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[ip] = {"attempts": 1, "blocked_until": 0}
        else:
            FAILED_ATTEMPTS[ip]["attempts"] += 1
            if FAILED_ATTEMPTS[ip]["attempts"] >= MAX_ATTEMPTS:
                FAILED_ATTEMPTS[ip]["blocked_until"] = now + LOCKOUT_TIME_SECONDS


def reset_failed_attempts(ip):
    with DB_LOCK:
        FAILED_ATTEMPTS.pop(ip, None)


# --- TIME & ATOMIC JSON PERSISTENCE ---
def get_bucharest_tz():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo("Europe/Bucharest")
    except ImportError:
        return timezone(timedelta(hours=2))


def get_local_time():
    return datetime.now(get_bucharest_tz()).strftime("%Y-%m-%d %H:%M:%S")


def get_today_support_key():
    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return hashlib.sha256(f"{today_date}-{SUPPORT_KEY_SALT}".encode("utf-8")).hexdigest()[:8]


def atomic_write_json(filepath, data):
    parent = os.path.dirname(filepath) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, filepath)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise


def load_json_file(filepath, fallback):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback
    return fallback


db_clienti = load_json_file(DB_FILE, {})
audit_log = load_json_file(AUDIT_FILE, [])
yara_alerts = load_json_file(YARA_FILE, [])
if not isinstance(db_clienti, dict):
    db_clienti = {}
if not isinstance(audit_log, list):
    audit_log = []
if not isinstance(yara_alerts, list):
    yara_alerts = []


def save_db():
    with DB_LOCK:
        atomic_write_json(DB_FILE, db_clienti)


def append_audit(event_type, hwid, hostname, ip, detail, severity="info"):
    with DB_LOCK:
        entry = {
            "id": uuid.uuid4().hex[:10],
            "time": get_local_time(),
            "ts": round(time.time(), 2),
            "type": event_type,
            "severity": severity,
            "hwid": hwid or "SYSTEM",
            "hostname": hostname or "Console",
            "ip": ip or "127.0.0.1",
            "detail": detail,
        }
        audit_log.insert(0, entry)
        del audit_log[MAX_AUDIT_ENTRIES:]
        atomic_write_json(AUDIT_FILE, audit_log)


def append_yara_alert(hwid, filename, rule, path, quarantine_path):
    with DB_LOCK:
        client = db_clienti.get(hwid, {})
        entry = {
            "id": uuid.uuid4().hex[:10],
            "time": get_local_time(),
            "ts": round(time.time(), 2),
            "hwid": hwid,
            "hostname": client.get("hostname", "Unknown"),
            "client_label": client.get("client_name") or client.get("hostname") or hwid,
            "filename": filename,
            "rule": rule,
            "path": path,
            "quarantine_path": quarantine_path,
        }
        yara_alerts.insert(0, entry)
        del yara_alerts[MAX_YARA_ENTRIES:]
        atomic_write_json(YARA_FILE, yara_alerts)


def compute_last_seen_ts(info):
    ts = info.get("last_seen_ts")
    if isinstance(ts, (int, float)) and ts > 0:
        return float(ts)
    last_seen_str = info.get("last_seen", "")
    if last_seen_str:
        try:
            dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=get_bucharest_tz()).timestamp()
        except Exception:
            pass
    return 0.0


def clamp_pct(val):
    try:
        return max(0, min(100, int(float(val))))
    except Exception:
        return None


# Generate Root CA certificate and key safely without shell=True
if not os.path.exists(CA_KEY) or not os.path.exists(CA_CRT):
    subprocess.run(["openssl", "genrsa", "-out", CA_KEY, "4096"], check=False)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            CA_KEY,
            "-sha256",
            "-days",
            "3650",
            "-out",
            CA_CRT,
            "-subj",
            "/CN=Sourceless-Root-CA/O=Sourceless-OS",
        ],
        check=False,
    )


# --- AUTH, CSRF & SECURITY HEADERS ---
def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/") or request.is_json or request.method == "POST":
                return jsonify({"error": "Session expired"}), 401
            return redirect(LOGIN_GATE_ROUTE)
        return f(*args, **kwargs)

    return decorated_function


def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected = session.get("csrf_token", "")
        provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        if not expected or not provided or not secrets.compare_digest(expected, provided):
            return jsonify({"error": "Invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)

    return decorated_function


@app.before_request
def dynamic_cookie_security():
    is_https = request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
    app.config["SESSION_COOKIE_SECURE"] = is_https


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# --- ROUTES ---
@app.route("/login")
def legacy_login():
    abort(404)


@app.route(LOGIN_GATE_ROUTE, methods=["GET", "POST"])
def login():
    client_ip = get_client_ip()
    csrf_token = get_csrf_token()

    if is_ip_blocked(client_ip):
        return render_template(
            "login.html",
            error="Too many failed attempts. Temporarily locked out.",
            csrf_token=csrf_token,
            logo_svg=SOURCELESS_LOGO_SVG,
        ), 429

    error = None
    if request.method == "POST":
        form_csrf = request.form.get("csrf_token", "")
        if not form_csrf or not secrets.compare_digest(csrf_token, form_csrf):
            error = "Security token mismatch. Please refresh and try again."
        else:
            user_input = request.form.get("username", "")
            pass_input = request.form.get("password", "")
            if user_input == ADMIN_USER and check_password_hash(ADMIN_PASSWORD_HASH, pass_input):
                reset_failed_attempts(client_ip)
                session["logged_in"] = True
                session["csrf_token"] = secrets.token_hex(32)
                append_audit("admin_login", "CONSOLE", "Operator", client_ip, f"Admin '{ADMIN_USER}' signed in", "ok")
                return redirect(url_for("dashboard"))
            record_failed_attempt(client_ip)
            append_audit("login_failed", "CONSOLE", "Operator", client_ip, "Failed console authentication attempt", "warn")
            error = "Invalid username or password!"

    return render_template("login.html", error=error, csrf_token=csrf_token, logo_svg=SOURCELESS_LOGO_SVG)


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")
    csr_pem = data.get("csr")
    client_ip = get_client_ip()

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid or missing HWID"}), 400

    with DB_LOCK:
        existing = db_clienti.get(hwid)
        if existing and existing.get("token") and not existing.get("allow_reenroll", False):
            provided_secret = request.headers.get("X-Sourceless-Secret", "")
            if not secrets.compare_digest(provided_secret, CLIENT_SECRET):
                append_audit(
                    "enroll_blocked",
                    hwid,
                    existing.get("hostname", "Unknown"),
                    client_ip,
                    "Blocked unauthorized re-enrollment attempt on already registered HWID",
                    "critical",
                )
                return jsonify({"error": "Device already enrolled. Admin re-enrollment approval required."}), 409

    device_token = str(uuid.uuid4())
    signed_cert = ""

    if csr_pem and "BEGIN CERTIFICATE REQUEST" in csr_pem:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                csr_file = os.path.join(tmpdir, "client.csr")
                crt_file = os.path.join(tmpdir, "client.crt")
                with open(csr_file, "w", encoding="utf-8") as f:
                    f.write(csr_pem)

                res = subprocess.run(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-in",
                        csr_file,
                        "-CA",
                        CA_CRT,
                        "-CAkey",
                        CA_KEY,
                        "-CAcreateserial",
                        "-out",
                        crt_file,
                        "-days",
                        "3650",
                        "-sha256",
                    ],
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode == 0 and os.path.exists(crt_file):
                    with open(crt_file, "r", encoding="utf-8") as f:
                        signed_cert = f.read()
        except Exception:
            pass

    with DB_LOCK:
        prev = db_clienti.get(hwid, {})
        db_clienti[hwid] = {
            "hostname": prev.get("hostname", ""),
            "client_name": prev.get("client_name", ""),
            "notes": prev.get("notes", ""),
            "ip": prev.get("ip", client_ip),
            "status": prev.get("status", "Inscris"),
            "support_state": "idle",
            "pending_cmd": "none",
            "pending_reinstate": False,
            "rustdesk_id": "N/A",
            "rustdesk_pw": "N/A",
            "last_seen": prev.get("last_seen", get_local_time()),
            "last_seen_ts": time.time(),
            "allow_reenroll": False,
            "revoked": prev.get("revoked", False),
            "os_version": prev.get("os_version", ""),
            "update_channel": prev.get("update_channel", "stable"),
            "update_status": prev.get("update_status", ""),
            "selinux": prev.get("selinux", ""),
            "lockdown": prev.get("lockdown", ""),
            "yara_active": prev.get("yara_active", True),
            "ram_percent": prev.get("ram_percent"),
            "disk_percent": prev.get("disk_percent"),
            "uptime": prev.get("uptime", ""),
            "token": device_token,
        }
        save_db()
        append_audit(
            "device_enrolled",
            hwid,
            prev.get("hostname") or "New Device",
            client_ip,
            "Device certificate and telemetry token issued",
            "ok",
        )

    return jsonify({"status": "registered", "token": device_token, "certificate": signed_cert})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(LOGIN_GATE_ROUTE)


@app.route("/")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        support_key=get_today_support_key(),
        csrf_token=get_csrf_token(),
        logo_svg=SOURCELESS_LOGO_SVG,
    )


@app.route("/api/data")
@login_required
def api_data():
    now_ts = time.time()
    public_clients = {}
    online_count = 0
    secure_count = 0
    pending_updates = 0

    with DB_LOCK:
        for hwid, info in db_clienti.items():
            seen_ts = compute_last_seen_ts(info)
            is_online = seen_ts > 0 and (now_ts - seen_ts) <= ONLINE_THRESHOLD_SECONDS
            if is_online:
                online_count += 1
            if not info.get("revoked") and info.get("status") == "Integru":
                secure_count += 1
            if info.get("update_status") == "pending_restart":
                pending_updates += 1

            sanitized = {k: v for k, v in info.items() if k != "token"}
            sanitized["last_seen_ts"] = seen_ts
            sanitized["online"] = is_online
            public_clients[hwid] = sanitized

        total = len(public_clients)
        stats = {
            "total": total,
            "online": online_count,
            "secure": secure_count,
            "compromised": total - secure_count,
            "pending_updates": pending_updates,
            "yara_alerts": len(yara_alerts),
        }
        recent_audit = list(audit_log[:40])
        recent_yara = list(yara_alerts[:40])

    return jsonify(
        {
            "clienti": public_clients,
            "stats": stats,
            "audit_log": recent_audit,
            "yara_alerts": recent_yara,
        }
    )


@app.route("/reinstate/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def reinstate_client(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    with DB_LOCK:
        if hwid in db_clienti:
            db_clienti[hwid]["pending_reinstate"] = True
            db_clienti[hwid]["status"] = "Integru"
            save_db()
            append_audit("tamper_reinstated", hwid, db_clienti[hwid].get("hostname", hwid), get_client_ip(), "Operator cleared tamper seal", "ok")
    return jsonify({"status": "ok"})


@app.route("/delete_client/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def delete_client(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    with DB_LOCK:
        if hwid in db_clienti:
            removed = db_clienti.pop(hwid, None) or {}
            save_db()
            append_audit("device_deleted", hwid, removed.get("hostname", hwid), get_client_ip(), "Device removed from fleet console", "warn")
            return jsonify({"status": "ok"})
    return jsonify({"error": "Client not found"}), 404


@app.route("/request_support/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def request_support(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    with DB_LOCK:
        if hwid in db_clienti:
            db_clienti[hwid]["pending_cmd"] = "start_support"
            db_clienti[hwid]["support_state"] = "waiting"
            save_db()
            append_audit("support_requested", hwid, db_clienti[hwid].get("hostname", hwid), get_client_ip(), "Requested interactive RustDesk support session", "info")
    return jsonify({"status": "ok"})


@app.route("/stop_support/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def stop_support(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    with DB_LOCK:
        if hwid in db_clienti:
            db_clienti[hwid]["pending_cmd"] = "stop_support"
            db_clienti[hwid]["support_state"] = "idle"
            db_clienti[hwid]["rustdesk_id"] = "N/A"
            db_clienti[hwid]["rustdesk_pw"] = "N/A"
            save_db()
            append_audit("support_stopped", hwid, db_clienti[hwid].get("hostname", hwid), get_client_ip(), "Terminated/reset remote support session", "info")
    return jsonify({"status": "ok"})


@app.route("/update_meta/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def update_meta(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    client_name = str(data.get("client_name", ""))[:80].strip()
    notes = str(data.get("notes", ""))[:500].strip()
    with DB_LOCK:
        if hwid not in db_clienti:
            return jsonify({"error": "Client not found"}), 404
        db_clienti[hwid]["client_name"] = client_name
        db_clienti[hwid]["notes"] = notes
        save_db()
        append_audit("meta_updated", hwid, db_clienti[hwid].get("hostname", hwid), get_client_ip(), f"Updated client label to '{client_name or 'Unassigned'}'", "info")
    return jsonify({"status": "ok"})


@app.route("/allow_reenroll/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def allow_reenroll(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    with DB_LOCK:
        if hwid not in db_clienti:
            return jsonify({"error": "Client not found"}), 404
        db_clienti[hwid]["allow_reenroll"] = True
        save_db()
        append_audit("reenroll_approved", hwid, db_clienti[hwid].get("hostname", hwid), get_client_ip(), "Approved one-time HWID re-enrollment", "warn")
    return jsonify({"status": "ok"})


@app.route("/device_cmd/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def device_cmd(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    cmd = str(data.get("cmd", "")).strip()
    if cmd not in ALLOWED_REMOTE_CMDS:
        return jsonify({"error": "Unsupported command"}), 400
    with DB_LOCK:
        if hwid not in db_clienti:
            return jsonify({"error": "Client not found"}), 404
        db_clienti[hwid]["pending_cmd"] = cmd
        save_db()
        append_audit("remote_command", hwid, db_clienti[hwid].get("hostname", hwid), get_client_ip(), f"Queued remote OS command: {cmd}", "info")
    return jsonify({"status": "ok"})


@app.route("/toggle_revoke/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def toggle_revoke(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    with DB_LOCK:
        if hwid not in db_clienti:
            return jsonify({"error": "Client not found"}), 404
        new_val = not bool(db_clienti[hwid].get("revoked", False))
        db_clienti[hwid]["revoked"] = new_val
        save_db()
        append_audit(
            "device_revoked" if new_val else "device_restored",
            hwid,
            db_clienti[hwid].get("hostname", hwid),
            get_client_ip(),
            "Device access revoked by operator" if new_val else "Device access restored by operator",
            "critical" if new_val else "ok",
        )
    return jsonify({"status": "ok", "revoked": new_val})


@app.route("/clear_yara_alerts", methods=["POST"])
@login_required
@csrf_protected
def clear_yara_alerts():
    with DB_LOCK:
        yara_alerts.clear()
        atomic_write_json(YARA_FILE, yara_alerts)
        append_audit("yara_cleared", "CONSOLE", "Operator", get_client_ip(), "Cleared all YARA threat alerts", "info")
    return jsonify({"status": "ok"})


@app.route("/api/client/submit_credentials", methods=["POST"])
def submit_credentials():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    with DB_LOCK:
        expected_token = db_clienti.get(hwid, {}).get("token") if hwid else None
        if not expected_token or not secrets.compare_digest(request.headers.get("X-Sourceless-Token", ""), expected_token):
            return jsonify({"error": "Unauthorized"}), 401

        if hwid in db_clienti:
            current_state = db_clienti[hwid].get("support_state")
            hostname = db_clienti[hwid].get("hostname", hwid)

            if current_state != "waiting" and data.get("status") == "approved":
                db_clienti[hwid]["pending_cmd"] = "stop_support"
                db_clienti[hwid]["support_state"] = "idle"
                db_clienti[hwid]["rustdesk_id"] = "N/A"
                db_clienti[hwid]["rustdesk_pw"] = "N/A"
            elif data.get("status") == "approved":
                db_clienti[hwid]["rustdesk_id"] = data.get("rustdesk_id")
                db_clienti[hwid]["rustdesk_pw"] = data.get("rustdesk_pw")
                db_clienti[hwid]["support_state"] = "approved"
                append_audit("support_approved", hwid, hostname, get_client_ip(), "User approved remote support credentials", "ok")
            else:
                db_clienti[hwid]["support_state"] = "rejected"
                db_clienti[hwid]["rustdesk_id"] = "Rejected"
                db_clienti[hwid]["rustdesk_pw"] = "N/A"
                append_audit("support_rejected", hwid, hostname, get_client_ip(), "User declined remote support request", "warn")

            save_db()
            return jsonify({"status": "ok"}), 200

    return jsonify({"error": "Client not found"}), 404


@app.route("/api/client/yara_alert", methods=["POST"])
def client_yara_alert():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    with DB_LOCK:
        expected_token = db_clienti.get(hwid, {}).get("token") if hwid else None
        if not expected_token or not secrets.compare_digest(request.headers.get("X-Sourceless-Token", ""), expected_token):
            return jsonify({"error": "Unauthorized"}), 401

        filename = str(data.get("filename", "unknown"))[:160]
        rule = str(data.get("rule", "UnknownRule"))[:120]
        path = str(data.get("path", ""))[:300]
        quarantine_path = str(data.get("quarantine_path", ""))[:300]
        hostname = db_clienti.get(hwid, {}).get("hostname", hwid)

        append_yara_alert(hwid, filename, rule, path, quarantine_path)
        append_audit("yara_threat", hwid, hostname, get_client_ip(), f"YARA blocked '{filename}' (rule: {rule})", "critical")

    return jsonify({"status": "recorded"}), 200


@app.route("/api/report", methods=["POST"])
def report_status():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")
    hostname = data.get("hostname")
    status = data.get("status")
    client_ip = get_client_ip()

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    with DB_LOCK:
        expected_token = db_clienti.get(hwid, {}).get("token") if hwid else None
        if not expected_token or not secrets.compare_digest(request.headers.get("X-Sourceless-Token", ""), expected_token):
            return jsonify({"error": "Unauthorized"}), 401

        if not hwid or not hostname or not status:
            return jsonify({"error": "Incomplete data."}), 400

        command = "none"
        current_client = db_clienti.get(hwid, {})
        prev_status = current_client.get("status")

        pending_cmd = current_client.get("pending_cmd", "")
        pending_reinstate = current_client.get("pending_reinstate", False)

        if pending_cmd:
            command = pending_cmd
            current_client["pending_cmd"] = ""
        elif pending_reinstate:
            command = "clear_tamper"
            status = "Integru"
            pending_reinstate = False

        if prev_status and prev_status != status and status != "Integru":
            append_audit("tamper_detected", hwid, hostname, client_ip, "System integrity status changed to Modified", "critical")
        elif prev_status and prev_status != "Integru" and status == "Integru":
            append_audit("status_restored", hwid, hostname, client_ip, "System integrity verified as Intact", "ok")

        os_version = str(data.get("os_version") or current_client.get("os_version", ""))[:64]
        update_channel = str(data.get("update_channel") or current_client.get("update_channel", "stable"))[:24]
        update_status = str(data.get("update_status") or current_client.get("update_status", ""))[:32]
        selinux = str(data.get("selinux") or current_client.get("selinux", ""))[:24]
        lockdown = str(data.get("lockdown") or current_client.get("lockdown", ""))[:32]
        uptime = str(data.get("uptime") or current_client.get("uptime", ""))[:32]
        ram_pct = clamp_pct(data.get("ram_percent")) if data.get("ram_percent") is not None else current_client.get("ram_percent")
        disk_pct = clamp_pct(data.get("disk_percent")) if data.get("disk_percent") is not None else current_client.get("disk_percent")
        yara_active = data.get("yara_active") if isinstance(data.get("yara_active"), bool) else current_client.get("yara_active", True)

        db_clienti[hwid] = {
            "hostname": hostname,
            "client_name": current_client.get("client_name", ""),
            "notes": current_client.get("notes", ""),
            "ip": client_ip,
            "status": status,
            "last_seen": get_local_time(),
            "last_seen_ts": time.time(),
            "pending_reinstate": pending_reinstate,
            "rustdesk_id": current_client.get("rustdesk_id", "N/A"),
            "rustdesk_pw": current_client.get("rustdesk_pw", "N/A"),
            "support_state": current_client.get("support_state", "idle"),
            "pending_cmd": current_client.get("pending_cmd", ""),
            "allow_reenroll": current_client.get("allow_reenroll", False),
            "revoked": current_client.get("revoked", False),
            "os_version": os_version,
            "update_channel": update_channel,
            "update_status": update_status,
            "selinux": selinux,
            "lockdown": lockdown,
            "yara_active": yara_active,
            "ram_percent": ram_pct,
            "disk_percent": disk_pct,
            "uptime": uptime,
            "token": expected_token,
        }
        save_db()

    return jsonify({"message": "Status received", "command": command}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
