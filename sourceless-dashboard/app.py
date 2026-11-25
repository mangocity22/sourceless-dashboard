from flask import Flask, Response, render_template, request, jsonify, redirect, url_for, session, abort
from datetime import datetime, timezone, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import hashlib
import io
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

# --- ENVIRONMENT & SECRETS CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from db import DashboardStore

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


def get_bucharest_tz():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo("Europe/Bucharest")
    except ImportError:
        return timezone(timedelta(hours=2))


def get_local_time():
    return datetime.now(get_bucharest_tz()).strftime("%Y-%m-%d %H:%M:%S")


app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

ADMIN_USER = get_cfg("DASHBOARD_ADMIN_USER", "admin")
ADMIN_PASS_RAW = get_cfg("DASHBOARD_ADMIN_PASS", "Sourceless2026!")
LOGIN_GATE_ROUTE = get_cfg("LOGIN_GATE_ROUTE", "/auth-console-gate")
CLIENT_SECRET = get_cfg("DASHBOARD_CLIENT_SECRET", "SourcelessClientAuth2026SecretKey!")
SUPPORT_KEY_SALT = get_cfg("SUPPORT_KEY_SALT", "SourcelessSecretSalt2026")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Directory & File Paths
DATA_DIR = "/opt/sourceless-dashboard" if os.path.isdir("/opt/sourceless-dashboard") else BASE_DIR
CA_DIR = os.path.join(DATA_DIR, "certs")


def compute_asset_version():
    """Return a short content hash of static assets for Cloudflare/browser cache busting."""
    h = hashlib.sha256()
    static_dir = os.path.join(BASE_DIR, "static")
    for rel in ("console.css", "console.js", "mesh.js"):
        fpath = os.path.join(static_dir, rel)
        if os.path.isfile(fpath):
            with open(fpath, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()[:10]


ASSET_VERSION = compute_asset_version()


@app.context_processor
def inject_global_template_vars():
    return {"asset_version": ASSET_VERSION}


CA_KEY = os.path.join(CA_DIR, "ca.key")
CA_CRT = os.path.join(CA_DIR, "ca.crt")
DB_FILE = os.path.join(DATA_DIR, "db_clienti.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.json")
YARA_FILE = os.path.join(DATA_DIR, "yara_alerts.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

ONLINE_THRESHOLD_SECONDS = 30
SUPPORT_WAITING_TIMEOUT_SECONDS = 180
MAX_AUDIT_ENTRIES = 100000
MAX_YARA_ENTRIES = 2000

ALLOWED_REMOTE_CMDS = {
    "check_update",
    "set_channel_stable",
    "set_channel_testing",
    "reboot_device",
}
REASON_REQUIRED_CMDS = {"reboot_device", "set_channel_stable", "set_channel_testing"}

os.makedirs(CA_DIR, exist_ok=True)
HWID_REGEX = re.compile(r"^[a-zA-Z0-9\-]{16,64}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
UPTIME_RE = re.compile(r"^(?:(\d+)d\s+)?(\d+)h\s+(\d+)m$")

store = DashboardStore(DATA_DIR)
store.migrate_legacy_json(
    {"clients": DB_FILE, "audit": AUDIT_FILE, "yara": YARA_FILE, "users": USERS_FILE},
    get_local_time(),
)
app.secret_key = get_cfg("DASHBOARD_SECRET_KEY") or store.get_or_create_secret(
    "session_secret", lambda: secrets.token_hex(32)
)

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


def is_live_iso_hostname(hostname):
    hn = (hostname or "").strip().lower()
    return hn.startswith("localhost-live") or hn in ("live-iso", "sourceless-live")


def get_client_ip():
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


# --- RATE LIMITING ---
MAX_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 900


def is_ip_blocked(ip):
    return store.is_ip_blocked(ip, MAX_ATTEMPTS)


def record_failed_attempt(ip):
    store.record_failed_attempt(ip, MAX_ATTEMPTS, LOCKOUT_TIME_SECONDS)


def reset_failed_attempts(ip):
    store.reset_failed_attempts(ip)


def get_today_support_key():
    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return hashlib.sha256(f"{today_date}-{SUPPORT_KEY_SALT}".encode("utf-8")).hexdigest()[:8]


def seed_primary_admin():
    """Ensures the primary administrator from env always exists and matches env credentials."""
    with store.write_tx():
        existing = store.get_user(ADMIN_USER)
        if existing and check_password_hash(existing.get("password_hash", ""), ADMIN_PASS_RAW):
            pwd_hash = existing["password_hash"]
        else:
            pwd_hash = generate_password_hash(ADMIN_PASS_RAW)
        store.upsert_user(
            {
                "username": ADMIN_USER,
                "full_name": existing.get("full_name", "Lead Administrator") if existing else "Lead Administrator",
                "role": "admin",
                "password_hash": pwd_hash,
                "active": True,
                "protected": True,
                "created_at": existing.get("created_at", get_local_time()) if existing else get_local_time(),
                "created_by": "system",
                "last_login": existing.get("last_login", "") if existing else "",
            }
        )


seed_primary_admin()


def current_actor():
    if session.get("logged_in"):
        return (
            session.get("username", ADMIN_USER),
            session.get("display_name", session.get("username", ADMIN_USER)),
            session.get("role", "support"),
        )
    return "SYSTEM", "Telemetry Agent", "system"


def append_audit(
    event_type,
    hwid,
    hostname,
    ip,
    detail,
    severity="info",
    category="system",
    reason="",
    actor=None,
    actor_name=None,
    actor_role=None,
):
    if actor is None:
        actor, actor_name, actor_role = current_actor()
    client_rec = (
        store.get_client(hwid)
        if hwid and hwid not in ("CONSOLE", "TEAM", "SYSTEM")
        else None
    )
    client_label = (client_rec or {}).get("client_name") or hostname or hwid or "System"
    entry = {
        "id": uuid.uuid4().hex[:10],
        "time": get_local_time(),
        "ts": round(time.time(), 2),
        "actor": actor,
        "actor_name": actor_name or actor,
        "actor_role": actor_role or "system",
        "category": category,
        "type": event_type,
        "severity": severity,
        "hwid": hwid or "SYSTEM",
        "hostname": hostname or "Console",
        "client_label": client_label,
        "ip": ip or "127.0.0.1",
        "detail": detail,
        "reason": (reason or "").strip(),
    }
    store.insert_audit(entry, trim=True, max_entries=MAX_AUDIT_ENTRIES)


def append_yara_alert(hwid, filename, rule, path, quarantine_path):
    client = store.get_client(hwid) or {}
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
    store.insert_yara_alert(entry, max_entries=MAX_YARA_ENTRIES)


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


def parse_uptime_minutes(uptime_str):
    if not uptime_str:
        return None
    m = UPTIME_RE.match(str(uptime_str).strip())
    if not m:
        return None
    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    mins = int(m.group(3) or 0)
    return (days * 1440) + (hours * 60) + mins


def auto_close_support_session(client_dict, hwid, reason_text, persist=True):
    """Reset active or pending remote support state and record an audit entry."""
    now_ts = time.time()
    client_dict["support_state"] = "idle"
    client_dict["rustdesk_id"] = "N/A"
    client_dict["rustdesk_pw"] = "N/A"
    client_dict["support_updated_ts"] = now_ts
    if client_dict.get("pending_cmd") == "start_support":
        client_dict["pending_cmd"] = ""
    if persist:
        store.update_client_fields(
            hwid,
            support_state="idle",
            rustdesk_id="N/A",
            rustdesk_pw="N/A",
            support_updated_ts=now_ts,
            pending_cmd=client_dict.get("pending_cmd", ""),
        )
    append_audit(
        "support_auto_closed",
        hwid,
        client_dict.get("hostname", hwid),
        client_dict.get("ip", ""),
        reason_text,
        "info",
        category="support",
        actor="SYSTEM",
        actor_name="Fleet Watchdog",
        actor_role="system",
        reason=reason_text,
    )


def require_reason(data, min_len=6):
    reason = str((data or {}).get("reason", "")).strip()
    if len(reason) < min_len or len(reason) > 400:
        return None, (
            jsonify({"error": f"Justification reason is required (between {min_len} and 400 characters)."}),
            400,
        )
    return reason, None


def filter_audit_entries(args):
    return store.query_audit(
        q=args.get("q") or "",
        actor=args.get("actor") or "",
        category=args.get("category") or "",
        severity=args.get("severity") or "",
        hwid=args.get("hwid") or "",
        days_raw=args.get("days") or "",
        limit=args.get("limit") or "250",
    )


def csv_safe_cell(val):
    s = "" if val is None else str(val)
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + s
    return s


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


# --- AUTH, RBAC, CSRF & SECURITY HEADERS ---
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
        uname = session.get("username")
        u = store.get_user(uname)
        if not u or not u.get("active", True):
            session.clear()
            if request.path.startswith("/api/") or request.is_json or request.method == "POST":
                return jsonify({"error": "Operator account disabled"}), 401
            return redirect(LOGIN_GATE_ROUTE)
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Administrator privileges required for this action"}), 403
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
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    else:
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# --- AUTH & VIEW ROUTES ---
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
            user_input = (request.form.get("username") or "").strip()
            pass_input = request.form.get("password") or ""
            with store.write_tx():
                user_rec = store.get_user(user_input)
                valid_user = bool(
                    user_rec
                    and user_rec.get("active", True)
                    and check_password_hash(user_rec.get("password_hash", ""), pass_input)
                )
                if valid_user:
                    store.update_user_fields(user_rec["username"], last_login=get_local_time())

            if valid_user:
                reset_failed_attempts(client_ip)
                session["logged_in"] = True
                session["username"] = user_rec["username"]
                session["display_name"] = user_rec.get("full_name") or user_rec["username"]
                session["role"] = user_rec.get("role", "support")
                session["csrf_token"] = secrets.token_hex(32)
                append_audit(
                    "operator_login",
                    "CONSOLE",
                    "Console",
                    client_ip,
                    f"Operator '{user_rec['username']}' ({session['role']}) authenticated",
                    "ok",
                    category="auth",
                    actor=user_rec["username"],
                    actor_name=session["display_name"],
                    actor_role=session["role"],
                )
                return redirect(url_for("dashboard"))

            record_failed_attempt(client_ip)
            append_audit(
                "login_failed",
                "CONSOLE",
                "Console",
                client_ip,
                f"Failed login attempt for username '{user_input or 'unknown'}'",
                "warn",
                category="auth",
                actor=user_input or "ANONYMOUS",
                actor_name=user_input or "Unknown",
                actor_role="anonymous",
            )
            error = "Invalid username, passphrase, or disabled account."

    return render_template("login.html", error=error, csrf_token=csrf_token, logo_svg=SOURCELESS_LOGO_SVG)


@app.route("/logout")
def logout():
    if session.get("logged_in"):
        actor, actor_name, actor_role = current_actor()
        append_audit(
            "operator_logout",
            "CONSOLE",
            "Console",
            get_client_ip(),
            f"Operator '{actor}' signed out",
            "info",
            category="auth",
            actor=actor,
            actor_name=actor_name,
            actor_role=actor_role,
        )
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
        current_user={
            "username": session.get("username", ADMIN_USER),
            "display_name": session.get("display_name", ADMIN_USER),
            "role": session.get("role", "support"),
        },
    )


# --- CONSOLE DATA & AUDIT APIs ---
@app.route("/api/data")
@login_required
def api_data():
    now_ts = time.time()
    public_clients = {}
    online_count = 0
    secure_count = 0
    pending_updates = 0

    with store.write_tx():
        clients = store.list_clients()
        for hwid, info in clients.items():
            seen_ts = compute_last_seen_ts(info)
            support_ts = float(info.get("support_updated_ts") or 0.0)
            s_state = info.get("support_state", "idle")
            effective_ts = max(seen_ts, support_ts)

            if s_state == "approved" and effective_ts > 0 and (now_ts - effective_ts) > ONLINE_THRESHOLD_SECONDS:
                auto_close_support_session(
                    info,
                    hwid,
                    "Remote support session auto-closed (device went offline / shut down)",
                    persist=True,
                )
            elif s_state == "waiting" and support_ts > 0 and (now_ts - support_ts) > SUPPORT_WAITING_TIMEOUT_SECONDS:
                auto_close_support_session(
                    info,
                    hwid,
                    "Pending remote support request expired (no response or device offline)",
                    persist=True,
                )

            is_online = seen_ts > 0 and (now_ts - seen_ts) <= ONLINE_THRESHOLD_SECONDS
            if is_online:
                online_count += 1
            if not info.get("revoked") and info.get("status") == "Integru":
                secure_count += 1
            if info.get("update_status") == "pending_restart":
                pending_updates += 1

            is_live_iso = is_live_iso_hostname(info.get("hostname", ""))
            sanitized = {k: v for k, v in info.items() if k != "token"}
            sanitized["last_seen_ts"] = seen_ts
            sanitized["online"] = is_online
            sanitized["is_live_iso"] = is_live_iso
            public_clients[hwid] = sanitized

        total = len(public_clients)
        orgs = sorted(
            {
                (c.get("organization") or "").strip()
                for c in public_clients.values()
                if (c.get("organization") or "").strip()
            }
        )
        offline_live_iso = sum(
            1 for c in public_clients.values() if c["is_live_iso"] and not c["online"]
        )
        stats = {
            "total": total,
            "online": online_count,
            "secure": secure_count,
            "compromised": total - secure_count,
            "pending_updates": pending_updates,
            "yara_alerts": store.count_yara_alerts(),
            "offline_live_iso": offline_live_iso,
        }
        recent_yara = store.list_yara_alerts(60)

    return jsonify(
        {
            "clienti": public_clients,
            "stats": stats,
            "organizations": orgs,
            "yara_alerts": recent_yara,
            "current_user": {
                "username": session.get("username", ADMIN_USER),
                "display_name": session.get("display_name", ADMIN_USER),
                "role": session.get("role", "support"),
            },
        }
    )


@app.route("/api/audit")
@login_required
def api_audit():
    entries, actors = filter_audit_entries(request.args)
    return jsonify({"entries": entries, "actors": actors, "total_matching": len(entries)})


@app.route("/api/audit/export.csv")
@login_required
def export_audit_csv():
    args = dict(request.args)
    args["limit"] = "5000"
    entries, _ = filter_audit_entries(args)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "Timestamp",
            "Operator",
            "Display Name",
            "Role",
            "Category",
            "Action",
            "Severity",
            "Target HWID",
            "Target Device",
            "IP Address",
            "Details",
            "Operator Justification",
        ]
    )
    for ev in entries:
        writer.writerow(
            [
                csv_safe_cell(ev.get("time", "")),
                csv_safe_cell(ev.get("actor", "")),
                csv_safe_cell(ev.get("actor_name", "")),
                csv_safe_cell(ev.get("actor_role", "")),
                csv_safe_cell(ev.get("category", "")),
                csv_safe_cell(ev.get("type", "")),
                csv_safe_cell(ev.get("severity", "")),
                csv_safe_cell(ev.get("hwid", "")),
                csv_safe_cell(ev.get("client_label", "")),
                csv_safe_cell(ev.get("ip", "")),
                csv_safe_cell(ev.get("detail", "")),
                csv_safe_cell(ev.get("reason", "")),
            ]
        )

    actor, actor_name, actor_role = current_actor()
    append_audit(
        "audit_exported",
        "CONSOLE",
        "Console",
        get_client_ip(),
        f"Exported {len(entries)} audit log rows to CSV",
        "info",
        category="auth",
        actor=actor,
        actor_name=actor_name,
        actor_role=actor_role,
    )

    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=sourceless-audit-log.csv"},
    )


# --- TEAM MANAGEMENT ROUTES (ADMIN ONLY) ---
@app.route("/api/team")
@login_required
@admin_required
def api_team():
    members = []
    for u in store.list_users():
        members.append(
            {
                "username": u.get("username"),
                "full_name": u.get("full_name", ""),
                "role": u.get("role", "support"),
                "active": bool(u.get("active", True)),
                "protected": bool(u.get("protected", False)),
                "created_at": u.get("created_at", ""),
                "created_by": u.get("created_by", ""),
                "last_login": u.get("last_login", ""),
            }
        )
    members.sort(key=lambda m: (0 if m["protected"] else 1, m["username"]))
    return jsonify({"members": members})


@app.route("/api/team/add", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def api_team_add():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    full_name = str(data.get("full_name", "")).strip()[:64]
    role = str(data.get("role", "support")).strip().lower()
    password = str(data.get("password", ""))
    reason, err = require_reason(data)
    if err:
        return err

    if not USERNAME_REGEX.match(username):
        return jsonify({"error": "Username must be 3-32 characters (letters, digits, _, ., -)."}), 400
    if role not in ("admin", "support"):
        return jsonify({"error": "Role must be 'admin' or 'support'."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

    with store.write_tx():
        if store.get_user(username):
            return jsonify({"error": "Username already exists."}), 409
        actor, _, _ = current_actor()
        store.upsert_user(
            {
                "username": username,
                "full_name": full_name or username,
                "role": role,
                "password_hash": generate_password_hash(password),
                "active": True,
                "protected": False,
                "created_at": get_local_time(),
                "created_by": actor,
                "last_login": "",
            }
        )
        append_audit(
            "operator_created",
            "TEAM",
            username,
            get_client_ip(),
            f"Created {role} operator account '{username}' ({full_name or username})",
            "ok",
            category="team",
            reason=reason,
        )
    return jsonify({"status": "ok"})


@app.route("/api/team/toggle/<target_user>", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def api_team_toggle(target_user):
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        rec = store.get_user(target_user)
        if not rec:
            return jsonify({"error": "Operator not found."}), 404
        if rec.get("protected") or target_user == ADMIN_USER:
            return jsonify({"error": "Primary administrator account cannot be disabled."}), 400
        new_active = not bool(rec.get("active", True))
        store.update_user_fields(target_user, active=new_active)
        append_audit(
            "operator_enabled" if new_active else "operator_disabled",
            "TEAM",
            target_user,
            get_client_ip(),
            f"{'Enabled' if new_active else 'Disabled'} operator account '{target_user}'",
            "warn" if not new_active else "ok",
            category="team",
            reason=reason,
        )
    return jsonify({"status": "ok", "active": new_active})


@app.route("/api/team/reset_password/<target_user>", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def api_team_reset_password(target_user):
    data = request.get_json(silent=True) or {}
    new_password = str(data.get("password", ""))
    reason, err = require_reason(data)
    if err:
        return err
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

    with store.write_tx():
        rec = store.get_user(target_user)
        if not rec:
            return jsonify({"error": "Operator not found."}), 404
        if rec.get("protected") or target_user == ADMIN_USER:
            return jsonify({"error": "Primary administrator password is managed via environment config."}), 400
        store.update_user_fields(target_user, password_hash=generate_password_hash(new_password))
        append_audit(
            "operator_password_reset",
            "TEAM",
            target_user,
            get_client_ip(),
            f"Reset passphrase for operator '{target_user}'",
            "warn",
            category="team",
            reason=reason,
        )
    return jsonify({"status": "ok"})


@app.route("/api/team/delete/<target_user>", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def api_team_delete(target_user):
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        rec = store.get_user(target_user)
        if not rec:
            return jsonify({"error": "Operator not found."}), 404
        if rec.get("protected") or target_user == ADMIN_USER or target_user == session.get("username"):
            return jsonify({"error": "Primary or active session administrator cannot be deleted."}), 400
        store.delete_user(target_user)
        append_audit(
            "operator_deleted",
            "TEAM",
            target_user,
            get_client_ip(),
            f"Deleted operator account '{target_user}'",
            "critical",
            category="team",
            reason=reason,
        )
    return jsonify({"status": "ok"})


# --- DEVICE ACTION ROUTES (WITH MANDATORY JUSTIFICATION) ---
@app.route("/reinstate/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def reinstate_client(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        client = store.get_client(hwid)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        store.update_client_fields(hwid, pending_reinstate=True, status="Integru")
        append_audit(
            "tamper_reinstated",
            hwid,
            client.get("hostname", hwid),
            get_client_ip(),
            "Operator cleared tamper seal and reinstated device integrity",
            "warn",
            category="security",
            reason=reason,
        )
    return jsonify({"status": "ok"})


@app.route("/delete_client/<hwid>", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def delete_client(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        removed = store.delete_client(hwid)
        if removed:
            append_audit(
                "device_deleted",
                hwid,
                removed.get("hostname", hwid),
                get_client_ip(),
                "Deleted device record from fleet database",
                "critical",
                category="access",
                reason=reason,
            )
            return jsonify({"status": "ok"})
    return jsonify({"error": "Client not found"}), 404


@app.route("/request_support/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def request_support(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        client = store.get_client(hwid)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        store.update_client_fields(
            hwid,
            pending_cmd="start_support",
            support_state="waiting",
            support_updated_ts=time.time(),
        )
        append_audit(
            "support_requested",
            hwid,
            client.get("hostname", hwid),
            get_client_ip(),
            "Dispatched interactive RustDesk support authorization prompt",
            "info",
            category="support",
            reason=reason,
        )
    return jsonify({"status": "ok"})


@app.route("/stop_support/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def stop_support(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "")).strip()[:400]
    with store.write_tx():
        client = store.get_client(hwid)
        if client:
            store.update_client_fields(
                hwid,
                pending_cmd="stop_support",
                support_state="idle",
                rustdesk_id="N/A",
                rustdesk_pw="N/A",
                support_updated_ts=time.time(),
            )
            append_audit(
                "support_stopped",
                hwid,
                client.get("hostname", hwid),
                get_client_ip(),
                "Terminated or reset remote support session",
                "info",
                category="support",
                reason=reason or "Session closed or rejected reset",
            )
    return jsonify({"status": "ok"})


@app.route("/update_meta/<hwid>", methods=["POST"])
@login_required
@csrf_protected
def update_meta(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    client_name = str(data.get("client_name", ""))[:80].strip()
    organization = str(data.get("organization", ""))[:80].strip()
    notes = str(data.get("notes", ""))[:500].strip()
    with store.write_tx():
        client = store.get_client(hwid)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        store.update_client_fields(
            hwid,
            client_name=client_name,
            organization=organization,
            notes=notes,
        )
        append_audit(
            "meta_updated",
            hwid,
            client.get("hostname", hwid),
            get_client_ip(),
            f"Updated device metadata (label: '{client_name or 'Unassigned'}', org: '{organization or 'None'}')",
            "info",
            category="access",
        )
    return jsonify({"status": "ok"})


@app.route("/api/bulk_cmd", methods=["POST"])
@login_required
@csrf_protected
def api_bulk_cmd():
    data = request.get_json(silent=True) or {}
    cmd = str(data.get("cmd", "")).strip()
    if cmd not in ALLOWED_REMOTE_CMDS:
        return jsonify({"error": "Unsupported command"}), 400
    raw_hwids = data.get("hwids")
    if not isinstance(raw_hwids, list) or not raw_hwids or len(raw_hwids) > 200:
        return jsonify({"error": "Select between 1 and 200 devices."}), 400

    reason, err = require_reason(data)
    if err:
        return err

    seen = set()
    targets = []
    for raw in raw_hwids:
        if is_valid_hwid(raw) and raw not in seen:
            seen.add(raw)
            targets.append(raw)
    if not targets:
        return jsonify({"error": "No valid device HWIDs provided."}), 400

    queued = 0
    skipped = 0
    client_ip = get_client_ip()
    with store.write_tx():
        for hwid in targets:
            client = store.get_client(hwid)
            if not client or client.get("revoked"):
                skipped += 1
                continue
            if cmd == "reboot_device" and client.get("support_state") in ("approved", "waiting"):
                auto_close_support_session(
                    client,
                    hwid,
                    "Remote support session auto-closed (bulk remote reboot initiated)",
                    persist=True,
                )
            store.update_client_fields(hwid, pending_cmd=cmd)
            append_audit(
                "bulk_remote_command",
                hwid,
                client.get("hostname", hwid),
                client_ip,
                f"Bulk remote command queued: {cmd}",
                "warn" if cmd in REASON_REQUIRED_CMDS else "info",
                category="updates",
                reason=reason,
            )
            queued += 1

    return jsonify({"status": "ok", "queued": queued, "skipped": skipped})


@app.route("/api/cleanup_live_iso", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def api_cleanup_live_iso():
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    now_ts = time.time()
    removed = 0
    with store.write_tx():
        clients = store.list_clients()
        for hwid, info in clients.items():
            if not is_live_iso_hostname(info.get("hostname", "")):
                continue
            seen_ts = compute_last_seen_ts(info)
            is_online = seen_ts > 0 and (now_ts - seen_ts) <= ONLINE_THRESHOLD_SECONDS
            if not is_online:
                if store.delete_client(hwid):
                    removed += 1
        append_audit(
            "live_iso_cleaned",
            "CONSOLE",
            "Console",
            get_client_ip(),
            f"Removed {removed} offline Live ISO device record(s)",
            "info",
            category="access",
            reason=reason,
        )
    return jsonify({"status": "ok", "removed": removed})


@app.route("/allow_reenroll/<hwid>", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def allow_reenroll(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        client = store.get_client(hwid)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        store.update_client_fields(hwid, allow_reenroll=True)
        append_audit(
            "reenroll_approved",
            hwid,
            client.get("hostname", hwid),
            get_client_ip(),
            "Approved one-time HWID re-enrollment",
            "warn",
            category="access",
            reason=reason,
        )
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

    reason = str(data.get("reason", "")).strip()[:400]
    if cmd in REASON_REQUIRED_CMDS:
        reason, err = require_reason(data)
        if err:
            return err

    with store.write_tx():
        client = store.get_client(hwid)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        if cmd == "reboot_device" and client.get("support_state") in ("approved", "waiting"):
            auto_close_support_session(
                client,
                hwid,
                "Remote support session auto-closed (remote reboot initiated)",
                persist=True,
            )
        store.update_client_fields(hwid, pending_cmd=cmd)
        append_audit(
            "remote_command",
            hwid,
            client.get("hostname", hwid),
            get_client_ip(),
            f"Queued remote command: {cmd}",
            "warn" if cmd in REASON_REQUIRED_CMDS else "info",
            category="updates",
            reason=reason,
        )
    return jsonify({"status": "ok"})


@app.route("/toggle_revoke/<hwid>", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def toggle_revoke(hwid):
    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        client = store.get_client(hwid)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        new_val = not bool(client.get("revoked", False))
        store.update_client_fields(hwid, revoked=new_val)
        append_audit(
            "device_revoked" if new_val else "device_restored",
            hwid,
            client.get("hostname", hwid),
            get_client_ip(),
            "Device access revoked by administrator" if new_val else "Device access restored by administrator",
            "critical" if new_val else "ok",
            category="access",
            reason=reason,
        )
    return jsonify({"status": "ok", "revoked": new_val})


@app.route("/clear_yara_alerts", methods=["POST"])
@login_required
@admin_required
@csrf_protected
def clear_yara_alerts():
    data = request.get_json(silent=True) or {}
    reason, err = require_reason(data)
    if err:
        return err

    with store.write_tx():
        count = store.clear_yara_alerts()
        append_audit(
            "yara_cleared",
            "CONSOLE",
            "Console",
            get_client_ip(),
            f"Cleared {count} YARA threat alert record(s)",
            "warn",
            category="yara",
            reason=reason,
        )
    return jsonify({"status": "ok"})


# --- DEVICE CLIENT ENDPOINTS ---
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")
    csr_pem = data.get("csr")
    client_ip = get_client_ip()

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid or missing HWID"}), 400

    with store.write_tx():
        existing = store.get_client(hwid)
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
                    category="security",
                    actor="DEVICE",
                    actor_name=existing.get("hostname", hwid),
                    actor_role="device",
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

    with store.write_tx():
        prev = store.get_client(hwid) or {}
        store.upsert_client(
            hwid,
            {
                "hostname": prev.get("hostname", ""),
                "client_name": prev.get("client_name", ""),
                "organization": prev.get("organization", ""),
                "notes": prev.get("notes", ""),
                "ip": prev.get("ip", client_ip),
                "status": prev.get("status", "Inscris"),
                "support_state": "idle",
                "support_updated_ts": 0.0,
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
            },
        )
        append_audit(
            "device_enrolled",
            hwid,
            prev.get("hostname") or "New Device",
            client_ip,
            "Device certificate and telemetry token issued",
            "ok",
            category="access",
            actor="DEVICE",
            actor_name=prev.get("hostname") or "New Device",
            actor_role="device",
        )

    return jsonify({"status": "registered", "token": device_token, "certificate": signed_cert})


@app.route("/api/client/submit_credentials", methods=["POST"])
def submit_credentials():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    with store.write_tx():
        client = store.get_client(hwid)
        expected_token = client.get("token") if client else None
        if not expected_token or not secrets.compare_digest(request.headers.get("X-Sourceless-Token", ""), expected_token):
            return jsonify({"error": "Unauthorized"}), 401

        if client:
            current_state = client.get("support_state")
            hostname = client.get("hostname", hwid)
            now_ts = time.time()
            fields = {
                "last_seen": get_local_time(),
                "last_seen_ts": now_ts,
                "support_updated_ts": now_ts,
            }

            if current_state != "waiting" and data.get("status") == "approved":
                fields["pending_cmd"] = "stop_support"
                fields["support_state"] = "idle"
                fields["rustdesk_id"] = "N/A"
                fields["rustdesk_pw"] = "N/A"
                store.update_client_fields(hwid, **fields)
            elif data.get("status") == "approved":
                fields["rustdesk_id"] = data.get("rustdesk_id") or "N/A"
                fields["rustdesk_pw"] = data.get("rustdesk_pw") or "N/A"
                fields["support_state"] = "approved"
                store.update_client_fields(hwid, **fields)
                append_audit(
                    "support_approved",
                    hwid,
                    hostname,
                    get_client_ip(),
                    "Local user approved remote support credentials",
                    "ok",
                    category="support",
                    actor="DEVICE",
                    actor_name=hostname,
                    actor_role="device",
                )
            else:
                fields["support_state"] = "rejected"
                fields["rustdesk_id"] = "Rejected"
                fields["rustdesk_pw"] = "N/A"
                store.update_client_fields(hwid, **fields)
                append_audit(
                    "support_rejected",
                    hwid,
                    hostname,
                    get_client_ip(),
                    "Local user declined remote support prompt",
                    "warn",
                    category="support",
                    actor="DEVICE",
                    actor_name=hostname,
                    actor_role="device",
                )

            return jsonify({"status": "ok"}), 200

    return jsonify({"error": "Client not found"}), 404


@app.route("/api/client/yara_alert", methods=["POST"])
def client_yara_alert():
    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid")

    if not is_valid_hwid(hwid):
        return jsonify({"error": "Invalid HWID"}), 400

    with store.write_tx():
        client = store.get_client(hwid)
        expected_token = client.get("token") if client else None
        if not expected_token or not secrets.compare_digest(request.headers.get("X-Sourceless-Token", ""), expected_token):
            return jsonify({"error": "Unauthorized"}), 401

        filename = str(data.get("filename", "unknown"))[:160]
        rule = str(data.get("rule", "UnknownRule"))[:120]
        path = str(data.get("path", ""))[:300]
        quarantine_path = str(data.get("quarantine_path", ""))[:300]
        hostname = client.get("hostname", hwid)

        append_yara_alert(hwid, filename, rule, path, quarantine_path)
        append_audit(
            "yara_threat",
            hwid,
            hostname,
            get_client_ip(),
            f"YARA quarantined '{filename}' (matched rule: {rule})",
            "critical",
            category="yara",
            actor="DEVICE",
            actor_name=hostname,
            actor_role="device",
        )

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

    with store.write_tx():
        current_client = store.get_client(hwid) or {}
        expected_token = current_client.get("token") if hwid else None
        if not expected_token or not secrets.compare_digest(request.headers.get("X-Sourceless-Token", ""), expected_token):
            return jsonify({"error": "Unauthorized"}), 401

        if not hwid or not hostname or not status:
            return jsonify({"error": "Incomplete data."}), 400

        command = "none"
        now_ts = time.time()
        prev_status = current_client.get("status")
        prev_seen_ts = compute_last_seen_ts(current_client)
        prev_uptime = current_client.get("uptime", "")
        incoming_uptime = str(data.get("uptime") or current_client.get("uptime", ""))[:32]

        s_state = current_client.get("support_state", "idle")
        support_ts = float(current_client.get("support_updated_ts") or 0.0)
        if s_state in ("approved", "waiting"):
            prev_mins = parse_uptime_minutes(prev_uptime)
            new_mins = parse_uptime_minutes(incoming_uptime)
            if prev_mins is not None and new_mins is not None and new_mins < prev_mins:
                auto_close_support_session(
                    current_client,
                    hwid,
                    "Remote support session auto-closed (device reboot detected)",
                    persist=False,
                )
            elif s_state == "approved" and prev_seen_ts > 0 and (now_ts - max(prev_seen_ts, support_ts)) > ONLINE_THRESHOLD_SECONDS:
                auto_close_support_session(
                    current_client,
                    hwid,
                    "Remote support session auto-closed (device reconnected after offline period)",
                    persist=False,
                )
                if not current_client.get("pending_cmd") and not current_client.get("pending_reinstate"):
                    current_client["pending_cmd"] = "stop_support"

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
            append_audit(
                "tamper_detected",
                hwid,
                hostname,
                client_ip,
                "System integrity status changed to Modified",
                "critical",
                category="security",
                actor="DEVICE",
                actor_name=hostname,
                actor_role="device",
            )
        elif prev_status and prev_status != "Integru" and status == "Integru":
            append_audit(
                "status_restored",
                hwid,
                hostname,
                client_ip,
                "System integrity verified as Intact",
                "ok",
                category="security",
                actor="DEVICE",
                actor_name=hostname,
                actor_role="device",
            )

        os_version = str(data.get("os_version") or current_client.get("os_version", ""))[:64]
        update_channel = str(data.get("update_channel") or current_client.get("update_channel", "stable"))[:24]
        update_status = str(data.get("update_status") or current_client.get("update_status", ""))[:32]
        selinux = str(data.get("selinux") or current_client.get("selinux", ""))[:24]
        lockdown = str(data.get("lockdown") or current_client.get("lockdown", ""))[:32]
        uptime = str(data.get("uptime") or current_client.get("uptime", ""))[:32]
        ram_pct = clamp_pct(data.get("ram_percent")) if data.get("ram_percent") is not None else current_client.get("ram_percent")
        disk_pct = clamp_pct(data.get("disk_percent")) if data.get("disk_percent") is not None else current_client.get("disk_percent")
        yara_active = data.get("yara_active") if isinstance(data.get("yara_active"), bool) else current_client.get("yara_active", True)

        store.upsert_client(
            hwid,
            {
                "hostname": hostname,
                "client_name": current_client.get("client_name", ""),
                "organization": current_client.get("organization", ""),
                "notes": current_client.get("notes", ""),
                "ip": client_ip,
                "status": status,
                "last_seen": get_local_time(),
                "last_seen_ts": now_ts,
                "pending_reinstate": pending_reinstate,
                "rustdesk_id": current_client.get("rustdesk_id", "N/A"),
                "rustdesk_pw": current_client.get("rustdesk_pw", "N/A"),
                "support_state": current_client.get("support_state", "idle"),
                "support_updated_ts": current_client.get("support_updated_ts", 0.0),
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
            },
        )

    return jsonify({"message": "Status received", "command": command}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
