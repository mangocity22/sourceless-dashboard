from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session, abort
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


app = Flask(__name__)

# Secret key must come from environment in production; falls back to an ephemeral runtime key
app.secret_key = get_cfg("DASHBOARD_SECRET_KEY") or secrets.token_hex(32)
ADMIN_USER = get_cfg("DASHBOARD_ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = generate_password_hash(get_cfg("DASHBOARD_ADMIN_PASS", "Sourceless2026!"))
LOGIN_GATE_ROUTE = get_cfg("LOGIN_GATE_ROUTE", "/auth-console-gate")
CLIENT_SECRET = get_cfg("DASHBOARD_CLIENT_SECRET", "SourcelessClientAuth2026SecretKey!")
SUPPORT_KEY_SALT = get_cfg("SUPPORT_KEY_SALT", "SourcelessSecretSalt2026")

# Security Cookie Settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Directory & File Paths
BASE_DIR = "/opt/sourceless-dashboard"
CA_DIR = f"{BASE_DIR}/certs"
CA_KEY = f"{CA_DIR}/ca.key"
CA_CRT = f"{CA_DIR}/ca.crt"
DB_FILE = f"{BASE_DIR}/db_clienti.json"
AUDIT_FILE = f"{BASE_DIR}/audit_log.json"

ONLINE_THRESHOLD_SECONDS = 30
MAX_AUDIT_ENTRIES = 120

os.makedirs(CA_DIR, exist_ok=True)

# Thread-safe persistence lock
DB_LOCK = threading.RLock()

# --- HWID VALIDATION REGEX ---
HWID_REGEX = re.compile(r"^[a-zA-Z0-9\-]{16,64}$")


def is_valid_hwid(hwid):
    """Validates HWID against safe structural format."""
    return bool(hwid and isinstance(hwid, str) and HWID_REGEX.match(hwid))


def get_client_ip():
    """Extracts real client IP address, including headers passed by Cloudflare Tunnel proxies."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


# --- RATE LIMITING / BRUTE-FORCE PROTECTION ---
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 900  # 15 minutes lockout


def is_ip_blocked(ip):
    """Checks if client IP is currently rate-limited."""
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
    """Increments failure count and triggers lockout if threshold is reached."""
    with DB_LOCK:
        now = time.time()
        if ip not in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[ip] = {"attempts": 1, "blocked_until": 0}
        else:
            FAILED_ATTEMPTS[ip]["attempts"] += 1
            if FAILED_ATTEMPTS[ip]["attempts"] >= MAX_ATTEMPTS:
                FAILED_ATTEMPTS[ip]["blocked_until"] = now + LOCKOUT_TIME_SECONDS


def reset_failed_attempts(ip):
    """Clears failure count on successful login."""
    with DB_LOCK:
        FAILED_ATTEMPTS.pop(ip, None)


# --- TIME & ATOMIC DATABASE HELPERS ---
def get_bucharest_tz():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo("Europe/Bucharest")
    except ImportError:
        return timezone(timedelta(hours=2))


def get_local_time():
    """Returns formatted timestamp for Europe/Bucharest timezone."""
    return datetime.now(get_bucharest_tz()).strftime("%Y-%m-%d %H:%M:%S")


def get_today_support_key():
    """Generates dynamic daily support key based on current UTC date."""
    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    input_str = f"{today_date}-{SUPPORT_KEY_SALT}"
    return hashlib.sha256(input_str.encode("utf-8")).hexdigest()[:8]


def atomic_write_json(filepath, data):
    """Writes JSON atomically using temporary file + fsync + os.replace."""
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
if not isinstance(db_clienti, dict):
    db_clienti = {}
if not isinstance(audit_log, list):
    audit_log = []


def save_db():
    """Thread-safe atomic persistence for client database."""
    with DB_LOCK:
        atomic_write_json(DB_FILE, db_clienti)


def append_audit(event_type, hwid, hostname, ip, detail, severity="info"):
    """Records a persistent audit timeline entry."""
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


def compute_last_seen_ts(info):
    """Returns epoch seconds for last_seen, supporting legacy string-only records."""
    ts = info.get("last_seen_ts")
    if isinstance(ts, (int, float)) and ts > 0:
        return float(ts)
    last_seen_str = info.get("last_seen", "")
    if last_seen_str:
        try:
            dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            dt = dt.replace(tzinfo=get_bucharest_tz())
            return dt.timestamp()
        except Exception:
            pass
    return 0.0


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
    """Enforces hardening security headers on all HTTP responses."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# Official SourceLess OS Hexagon SVG Brand Mark
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

CONSTELLATION_SCRIPT = """
(function() {
  const canvas = document.getElementById('sl-mesh');
  if (!canvas) return;
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) { canvas.style.display = 'none'; return; }
  const ctx = canvas.getContext('2d');
  let w = 0, h = 0, raf = 0;
  const pointer = { x: -9999, y: -9999 };
  const nodes = [];
  const NODE_COUNT = 44;

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    w = window.innerWidth;
    h = window.innerHeight;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function seed() {
    nodes.length = 0;
    for (let i = 0; i < NODE_COUNT; i++) {
      nodes.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.32,
        vy: (Math.random() - 0.5) * 0.32,
        r: 1.3 + Math.random() * 1.4,
        lime: i % 5 === 0
      });
    }
  }

  function frame() {
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      a.x += a.vx;
      a.y += a.vy;
      if (a.x < 0 || a.x > w) a.vx *= -1;
      if (a.y < 0 || a.y > h) a.vy *= -1;

      const dxp = pointer.x - a.x;
      const dyp = pointer.y - a.y;
      const dp = Math.hypot(dxp, dyp);
      if (dp < 160 && dp > 1) {
        a.x -= (dxp / dp) * 0.18;
        a.y -= (dyp / dp) * 0.18;
      }

      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < 145) {
          const alpha = (1 - d / 145) * 0.16;
          ctx.strokeStyle = (a.lime || b.lime)
            ? `rgba(167, 255, 82, ${alpha.toFixed(3)})`
            : `rgba(96, 84, 242, ${(alpha * 1.35).toFixed(3)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      if (dp < 185) {
        const alpha = (1 - dp / 185) * 0.28;
        ctx.strokeStyle = `rgba(167, 255, 82, ${alpha.toFixed(3)})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(pointer.x, pointer.y);
        ctx.stroke();
      }

      ctx.fillStyle = a.lime ? 'rgba(167, 255, 82, 0.55)' : 'rgba(148, 155, 192, 0.42)';
      ctx.beginPath();
      ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
      ctx.fill();
    }
    raf = requestAnimationFrame(frame);
  }

  window.addEventListener('resize', resize);
  window.addEventListener('pointermove', (e) => { pointer.x = e.clientX; pointer.y = e.clientY; }, { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(raf); }
    else { cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); }
  });

  resize();
  seed();
  raf = requestAnimationFrame(frame);
})();
"""


# --- TEMPLATES ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SourceLess OS // Support Gate</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #070910;
    --card: rgba(15, 18, 30, 0.78);
    --input: rgba(8, 11, 19, 0.9);
    --border: rgba(255, 255, 255, 0.09);
    --indigo: #6054F2;
    --lime: #A7FF52;
    --text: #E8ECFF;
    --muted: #949BC0;
    --red: #F2546D;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    background: radial-gradient(circle at 20% 20%, rgba(96, 84, 242, 0.16), transparent 45%),
                radial-gradient(circle at 80% 80%, rgba(167, 255, 82, 0.08), transparent 45%),
                var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    overflow: hidden;
  }
  #sl-mesh {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
  }
  .login-shell {
    position: relative;
    z-index: 2;
    width: 100%;
    max-width: 420px;
    animation: cardEnter 0.55s cubic-bezier(0.22, 1, 0.36, 1) both;
  }
  @keyframes cardEnter {
    from { opacity: 0; transform: translateY(16px) scale(0.98); }
    to { opacity: 1; transform: translateY(0) scale(1); }
  }
  .login-card {
    position: relative;
    background: var(--card);
    backdrop-filter: blur(22px) saturate(140%);
    -webkit-backdrop-filter: blur(22px) saturate(140%);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 36px 34px 32px;
    box-shadow: 0 28px 70px rgba(0, 0, 0, 0.58), inset 0 1px 0 rgba(255, 255, 255, 0.08);
    overflow: hidden;
  }
  .login-card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(360px circle at var(--mx, 50%) var(--my, 15%), rgba(96, 84, 242, 0.14), transparent 70%);
    pointer-events: none;
    transition: opacity 0.25s;
  }
  .brand-head {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    margin-bottom: 28px;
  }
  .brand-mark {
    width: 56px;
    height: 56px;
    margin-bottom: 14px;
    filter: drop-shadow(0 0 18px rgba(167, 255, 82, 0.22));
    animation: hexFloat 5s ease-in-out infinite;
  }
  @keyframes hexFloat {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-4px); }
  }
  .brand-head h1 {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 1.55rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text);
  }
  .brand-sub {
    margin-top: 6px;
    font-size: 0.85rem;
    color: var(--muted);
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .dot-live {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--lime);
    box-shadow: 0 0 10px var(--lime);
  }
  .error-banner {
    background: rgba(242, 84, 109, 0.14);
    border: 1px solid rgba(242, 84, 109, 0.42);
    color: #FFA3B3;
    padding: 11px 14px;
    border-radius: 10px;
    font-size: 0.85rem;
    margin-bottom: 18px;
    text-align: center;
    animation: shakeX 0.35s ease;
  }
  @keyframes shakeX {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-6px); }
    75% { transform: translateX(6px); }
  }
  .field {
    margin-bottom: 18px;
  }
  .field label {
    display: block;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 8px;
  }
  .field input {
    width: 100%;
    padding: 12px 14px;
    background: var(--input);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text);
    font-size: 0.94rem;
    font-family: inherit;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  .field input:focus {
    border-color: var(--indigo);
    box-shadow: 0 0 0 3px rgba(96, 84, 242, 0.24);
  }
  .btn-submit {
    width: 100%;
    margin-top: 6px;
    padding: 13px 18px;
    border: none;
    border-radius: 10px;
    background: linear-gradient(135deg, #6054F2, #4E43D8);
    color: #FFFFFF;
    font-size: 0.95rem;
    font-weight: 700;
    font-family: inherit;
    cursor: pointer;
    box-shadow: 0 10px 26px rgba(96, 84, 242, 0.34);
    transition: transform 0.16s, box-shadow 0.2s, filter 0.2s;
  }
  .btn-submit:hover {
    filter: brightness(1.1);
    transform: translateY(-1px);
    box-shadow: 0 14px 32px rgba(96, 84, 242, 0.45);
  }
  .btn-submit:active { transform: translateY(0); }
  .gate-foot {
    margin-top: 20px;
    text-align: center;
    font-size: 0.76rem;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }
  @media (prefers-reduced-motion: reduce) {
    .login-shell, .brand-mark, .error-banner { animation: none; }
  }
</style>
</head>
<body>
<canvas id="sl-mesh"></canvas>
<div class="login-shell">
  <div class="login-card" id="loginCard">
    <div class="brand-head">
      <div class="brand-mark">""" + SOURCELESS_LOGO_SVG + """</div>
      <h1>SourceLess OS</h1>
      <div class="brand-sub"><span class="dot-live"></span> Fleet Operations &amp; Support Gate</div>
    </div>
    {% if error %}
    <div class="error-banner">{{ error }}</div>
    {% endif %}
    <form method="POST">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <div class="field">
        <label for="username">Operator Username</label>
        <input id="username" type="text" name="username" autocomplete="username" required autofocus>
      </div>
      <div class="field">
        <label for="password">Passphrase</label>
        <input id="password" type="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-submit">Authenticate Console</button>
    </form>
    <div class="gate-foot">TLS TUNNEL • RATE-LIMIT GUARD ACTIVE</div>
  </div>
</div>
<script>
""" + CONSTELLATION_SCRIPT + """
(function() {
  const card = document.getElementById('loginCard');
  if (!card) return;
  card.addEventListener('pointermove', (e) => {
    const r = card.getBoundingClientRect();
    card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
    card.style.setProperty('--my', (e.clientY - r.top) + 'px');
  }, { passive: true });
})();
</script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="{{ csrf_token }}">
<title>SourceLess OS // Support &amp; Telemetry Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #070910;
    --bg-elev: rgba(15, 19, 32, 0.72);
    --bg-solid: #0E1220;
    --bg-input: rgba(9, 12, 21, 0.92);
    --border: rgba(255, 255, 255, 0.085);
    --border-bright: rgba(96, 84, 242, 0.52);
    --indigo: #6054F2;
    --indigo-soft: rgba(96, 84, 242, 0.18);
    --lime: #A7FF52;
    --green: #2AC3A2;
    --amber: #F5A623;
    --red: #F2546D;
    --text: #E8ECFF;
    --muted: #949BC0;
    --ease-spring: cubic-bezier(0.22, 1, 0.36, 1);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    background:
      radial-gradient(900px circle at 12% -10%, rgba(96, 84, 242, 0.14), transparent 55%),
      radial-gradient(760px circle at 92% 8%, rgba(167, 255, 82, 0.06), transparent 52%),
      var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 26px 24px 48px;
    overflow-x: hidden;
  }
  #sl-mesh {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
  }
  .shell {
    position: relative;
    z-index: 1;
    max-width: 1480px;
    margin: 0 auto;
    animation: pageIn 0.45s var(--ease-spring) both;
  }
  @keyframes pageIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  /* Header Telemetry Bar */
  .topbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 14px 20px;
    margin-bottom: 24px;
    background: var(--bg-elev);
    backdrop-filter: blur(18px) saturate(140%);
    -webkit-backdrop-filter: blur(18px) saturate(140%);
    border: 1px solid var(--border);
    border-radius: 16px;
    box-shadow: 0 14px 36px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.06);
  }
  .brand-group {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .brand-logo {
    width: 38px;
    height: 38px;
    flex-shrink: 0;
    filter: drop-shadow(0 0 12px rgba(167, 255, 82, 0.24));
  }
  .brand-titles h1 {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 1.2rem;
    font-weight: 700;
    letter-spacing: -0.015em;
    color: var(--text);
  }
  .live-telemetry {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 2px;
    font-size: 0.76rem;
    color: var(--muted);
  }
  .ecg-svg {
    width: 44px;
    height: 14px;
    overflow: visible;
  }
  .ecg-line {
    fill: none;
    stroke: var(--lime);
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-dasharray: 90;
    stroke-dashoffset: 90;
    animation: ecgPulse 2.6s linear infinite;
  }
  @keyframes ecgPulse {
    0% { stroke-dashoffset: 90; opacity: 0.35; }
    50% { stroke-dashoffset: 0; opacity: 1; }
    100% { stroke-dashoffset: -90; opacity: 0.35; }
  }
  .topbar-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }
  .key-pill {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 7px 10px 7px 14px;
    font-size: 0.82rem;
  }
  .key-pill .lbl { color: var(--muted); }
  .key-pill .val {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 0.94rem;
    color: var(--lime);
    letter-spacing: 0.04em;
  }
  .btn-chip {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 0.82rem;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    transition: background 0.16s, border-color 0.16s, transform 0.14s;
  }
  .btn-chip:hover {
    background: rgba(96, 84, 242, 0.18);
    border-color: var(--border-bright);
    transform: translateY(-1px);
  }
  .btn-chip.danger:hover {
    background: rgba(242, 84, 109, 0.18);
    border-color: rgba(242, 84, 109, 0.55);
  }
  .btn-mini-copy {
    background: rgba(96, 84, 242, 0.16);
    border: 1px solid rgba(96, 84, 242, 0.36);
    color: var(--text);
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 0.74rem;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: background 0.15s, transform 0.12s;
  }
  .btn-mini-copy:hover { background: rgba(96, 84, 242, 0.32); }

  /* KPI Spotlight Grid */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 22px;
  }
  .kpi-card {
    position: relative;
    background: var(--bg-elev);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 22px;
    overflow: hidden;
    transition: border-color 0.25s, transform 0.2s var(--ease-spring);
  }
  .kpi-card:hover {
    transform: translateY(-2px);
    border-color: rgba(255, 255, 255, 0.16);
  }
  .kpi-card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(240px circle at var(--mx, 50%) var(--my, 50%), rgba(96, 84, 242, 0.16), transparent 72%);
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.25s;
  }
  .kpi-card:hover::before { opacity: 1; }
  .kpi-card::after {
    content: "";
    position: absolute;
    left: 0;
    top: 16px;
    bottom: 16px;
    width: 3px;
    border-radius: 0 3px 3px 0;
    background: var(--indigo);
  }
  .kpi-card.online::after { background: var(--lime); box-shadow: 0 0 12px rgba(167, 255, 82, 0.5); }
  .kpi-card.secure::after { background: var(--green); box-shadow: 0 0 12px rgba(42, 195, 162, 0.45); }
  .kpi-card.alert::after { background: var(--red); box-shadow: 0 0 12px rgba(242, 84, 109, 0.5); }
  .kpi-label {
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 8px;
  }
  .kpi-value {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 2.15rem;
    font-weight: 700;
    color: var(--text);
    line-height: 1.05;
    font-variant-numeric: tabular-nums;
  }
  .kpi-sub {
    margin-top: 6px;
    font-size: 0.76rem;
    color: var(--muted);
  }

  /* Toolbar: Search + Filter Pills */
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    margin-bottom: 16px;
  }
  .search-wrap {
    position: relative;
    flex: 1 1 300px;
    max-width: 440px;
  }
  .search-wrap input {
    width: 100%;
    padding: 11px 14px 11px 38px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 12px;
    color: var(--text);
    font-size: 0.88rem;
    font-family: inherit;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  .search-wrap input:focus {
    border-color: var(--indigo);
    box-shadow: 0 0 0 3px rgba(96, 84, 242, 0.22);
  }
  .search-icon {
    position: absolute;
    left: 12px;
    top: 50%;
    transform: translateY(-50%);
    width: 16px;
    height: 16px;
    color: var(--muted);
    pointer-events: none;
  }
  .filter-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .filter-pill {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: 999px;
    padding: 8px 14px;
    font-size: 0.8rem;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.18s;
  }
  .filter-pill:hover {
    color: var(--text);
    border-color: rgba(255, 255, 255, 0.18);
  }
  .filter-pill.active {
    background: var(--indigo-soft);
    color: #FFFFFF;
    border-color: var(--indigo);
    box-shadow: 0 0 18px rgba(96, 84, 242, 0.25);
  }

  /* Fleet Table */
  .table-shell {
    background: var(--bg-elev);
    backdrop-filter: blur(18px) saturate(140%);
    -webkit-backdrop-filter: blur(18px) saturate(140%);
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow-x: auto;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.42);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    min-width: 960px;
  }
  th {
    background: rgba(10, 13, 24, 0.8);
    color: var(--muted);
    font-size: 0.74rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 14px 18px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.045);
    font-size: 0.87rem;
    vertical-align: middle;
  }
  tbody tr {
    transition: background 0.18s;
  }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: rgba(96, 84, 242, 0.07); }
  tbody tr.row-flash { animation: rowGlow 0.9s ease; }
  @keyframes rowGlow {
    0% { background: rgba(167, 255, 82, 0.15); }
    100% { background: transparent; }
  }

  /* Status & Radar Indicator */
  .presence {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 0.8rem;
    font-weight: 600;
  }
  .presence.on { color: var(--lime); }
  .presence.off { color: var(--muted); }
  .radar-dot {
    position: relative;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
  }
  .presence.on .radar-dot::after {
    content: "";
    position: absolute;
    inset: -4px;
    border-radius: 50%;
    border: 1.5px solid var(--lime);
    animation: radarPing 2s cubic-bezier(0, 0, 0.2, 1) infinite;
  }
  @keyframes radarPing {
    0% { transform: scale(0.75); opacity: 0.9; }
    80%, 100% { transform: scale(2.1); opacity: 0; }
  }

  .device-cell {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .client-name {
    font-weight: 700;
    color: #FFFFFF;
    font-size: 0.92rem;
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }
  .host-sub {
    font-size: 0.76rem;
    color: var(--muted);
  }
  .hwid-btn, .cred-chip {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--text);
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 5px 9px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: border-color 0.15s, background 0.15s, transform 0.1s;
  }
  .hwid-btn { max-width: 175px; }
  .hwid-txt {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .hwid-btn:hover, .cred-chip:hover {
    border-color: var(--lime);
    background: rgba(167, 255, 82, 0.08);
  }
  .cred-chip { color: #9DE8FF; margin-right: 5px; margin-bottom: 3px; }
  .copied-flash {
    border-color: var(--lime) !important;
    box-shadow: 0 0 12px rgba(167, 255, 82, 0.35);
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 5px 11px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 700;
  }
  .badge-secure {
    background: rgba(42, 195, 162, 0.14);
    color: var(--green);
    border: 1px solid rgba(42, 195, 162, 0.35);
  }
  .badge-alert {
    background: rgba(242, 84, 109, 0.15);
    color: #FF8DA0;
    border: 1px solid rgba(242, 84, 109, 0.38);
  }
  .badge-waiting {
    background: rgba(245, 166, 35, 0.14);
    color: var(--amber);
    border: 1px solid rgba(245, 166, 35, 0.38);
  }
  .spin-ring {
    width: 10px;
    height: 10px;
    border: 2px solid rgba(245, 166, 35, 0.3);
    border-top-color: var(--amber);
    border-radius: 50%;
    animation: spin 0.9s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Action Buttons */
  .actions-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .btn {
    border: none;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 0.78rem;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    transition: transform 0.12s, filter 0.15s, opacity 0.15s;
  }
  .btn:hover:not(:disabled) { transform: translateY(-1px); filter: brightness(1.1); }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-primary { background: var(--indigo); color: #FFFFFF; }
  .btn-support { background: rgba(42, 195, 162, 0.2); color: #7AF2D8; border: 1px solid rgba(42, 195, 162, 0.42); }
  .btn-danger { background: rgba(242, 84, 109, 0.22); color: #FFA2B2; border: 1px solid rgba(242, 84, 109, 0.45); }
  .btn-ghost {
    background: rgba(255, 255, 255, 0.04);
    color: var(--muted);
    border: 1px solid var(--border);
  }
  .btn-ghost:hover:not(:disabled) { color: #FFFFFF; border-color: rgba(255, 255, 255, 0.2); }

  .empty-state {
    text-align: center;
    padding: 52px 20px;
    color: var(--muted);
    font-size: 0.92rem;
  }

  /* Slide-Over Drawers & Modal */
  .drawer-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(4, 6, 12, 0.62);
    backdrop-filter: blur(4px);
    z-index: 40;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.25s ease;
  }
  .drawer-backdrop.open {
    opacity: 1;
    pointer-events: auto;
  }
  .drawer {
    position: fixed;
    top: 16px;
    right: 16px;
    bottom: 16px;
    width: min(440px, calc(100vw - 32px));
    background: rgba(13, 17, 29, 0.94);
    backdrop-filter: blur(24px) saturate(140%);
    -webkit-backdrop-filter: blur(24px) saturate(140%);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 18px;
    box-shadow: -12px 0 48px rgba(0, 0, 0, 0.65);
    z-index: 50;
    display: flex;
    flex-direction: column;
    transform: translateX(calc(100% + 24px));
    transition: transform 0.36s var(--ease-spring);
  }
  .drawer.open { transform: translateX(0); }
  .drawer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 20px;
    border-bottom: 1px solid var(--border);
  }
  .drawer-head h2 {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 1.08rem;
    color: var(--text);
  }
  .drawer-body {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .field-group label {
    display: block;
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .field-group input, .field-group textarea {
    width: 100%;
    padding: 10px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text);
    font-size: 0.88rem;
    font-family: inherit;
    outline: none;
  }
  .field-group input:focus, .field-group textarea:focus {
    border-color: var(--indigo);
  }
  .meta-box {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 14px;
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 8px 14px;
    font-size: 0.8rem;
  }
  .meta-box .mk { color: var(--muted); }
  .meta-box .mv { color: var(--text); font-family: 'JetBrains Mono', monospace; word-break: break-all; }

  /* Audit Timeline */
  .audit-item {
    position: relative;
    padding: 10px 12px 10px 20px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border);
  }
  .audit-item::before {
    content: "";
    position: absolute;
    left: 9px;
    top: 15px;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--indigo);
  }
  .audit-item.sev-critical::before { background: var(--red); box-shadow: 0 0 8px var(--red); }
  .audit-item.sev-ok::before { background: var(--green); }
  .audit-item.sev-warn::before { background: var(--amber); }
  .audit-top {
    display: flex;
    justify-content: space-between;
    font-size: 0.74rem;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .audit-msg { font-size: 0.82rem; color: var(--text); }

  /* Custom Glass Confirm Modal */
  .modal {
    position: fixed;
    left: 50%;
    top: 50%;
    transform: translate(-50%, -46%) scale(0.95);
    width: min(420px, calc(100vw - 32px));
    background: rgba(14, 18, 31, 0.96);
    backdrop-filter: blur(22px);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 28px 68px rgba(0, 0, 0, 0.72);
    z-index: 60;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s, transform 0.25s var(--ease-spring);
  }
  .modal.open {
    opacity: 1;
    pointer-events: auto;
    transform: translate(-50%, -50%) scale(1);
  }
  .modal h3 { font-family: 'Space Grotesk', sans-serif; font-size: 1.08rem; margin-bottom: 8px; }
  .modal p { font-size: 0.86rem; color: var(--muted); line-height: 1.45; margin-bottom: 20px; }
  .modal-btns { display: flex; justify-content: flex-end; gap: 10px; }

  /* Toast Stack */
  .toast-stack {
    position: fixed;
    right: 20px;
    bottom: 20px;
    z-index: 70;
    display: flex;
    flex-direction: column;
    gap: 8px;
    pointer-events: none;
  }
  .toast {
    background: rgba(15, 20, 34, 0.94);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(167, 255, 82, 0.38);
    color: var(--text);
    padding: 10px 16px;
    border-radius: 10px;
    font-size: 0.83rem;
    font-weight: 600;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);
    animation: toastIn 0.28s var(--ease-spring) both;
  }
  @keyframes toastIn {
    from { opacity: 0; transform: translateY(10px) scale(0.96); }
    to { opacity: 1; transform: translateY(0) scale(1); }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
  }
</style>
</head>
<body>
<canvas id="sl-mesh"></canvas>

<div class="shell">
  <header class="topbar">
    <div class="brand-group">
      <div class="brand-logo">""" + SOURCELESS_LOGO_SVG + """</div>
      <div class="brand-titles">
        <h1>SourceLess OS Fleet Console</h1>
        <div class="live-telemetry">
          <svg class="ecg-svg" viewBox="0 0 44 14" aria-hidden="true">
            <polyline class="ecg-line" points="0,8 10,8 14,2 19,12 24,4 28,8 44,8" />
          </svg>
          <span id="syncLabel">Live telemetry sync • 2s</span>
        </div>
      </div>
    </div>

    <div class="topbar-actions">
      <div class="key-pill">
        <span class="lbl">Support Key (UTC)</span>
        <span class="val" id="supportKeyVal">{{ support_key }}</span>
        <button class="btn-mini-copy" type="button" id="copyKeyBtn">Copy</button>
      </div>
      <button class="btn-chip" type="button" id="openAuditBtn">Audit Log</button>
      <a href="/logout" class="btn-chip danger">Logout</a>
    </div>
  </header>

  <section class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Registered MiniPCs</div>
      <div class="kpi-value" id="stat-total">0</div>
      <div class="kpi-sub">Enrolled hardware identities</div>
    </div>
    <div class="kpi-card online">
      <div class="kpi-label">Online Now</div>
      <div class="kpi-value" id="stat-online">0</div>
      <div class="kpi-sub">Heartbeat within 30s</div>
    </div>
    <div class="kpi-card secure">
      <div class="kpi-label">Integrity Intact</div>
      <div class="kpi-value" id="stat-secure">0</div>
      <div class="kpi-sub">SELinux + Immutable Verified</div>
    </div>
    <div class="kpi-card alert">
      <div class="kpi-label">Tamper Alerts</div>
      <div class="kpi-value" id="stat-compromised">0</div>
      <div class="kpi-sub">Modified or emergency shell active</div>
    </div>
  </section>

  <div class="toolbar">
    <div class="search-wrap">
      <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"></circle><path d="m21 21-4.3-4.3"></path>
      </svg>
      <input id="searchInput" type="search" placeholder="Search by client name, hostname, HWID, IP or notes...">
    </div>
    <div class="filter-pills" id="filterPills">
      <button class="filter-pill active" data-filter="all" type="button">All</button>
      <button class="filter-pill" data-filter="online" type="button">Online</button>
      <button class="filter-pill" data-filter="offline" type="button">Offline</button>
      <button class="filter-pill" data-filter="modified" type="button">Tamper / Modified</button>
      <button class="filter-pill" data-filter="support" type="button">Support Active</button>
    </div>
  </div>

  <div class="table-shell">
    <table>
      <thead>
        <tr>
          <th>Presence</th>
          <th>Client / Device</th>
          <th>HWID</th>
          <th>Network &amp; Last Sync</th>
          <th>Integrity</th>
          <th>Remote Support</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="clients-tbody"></tbody>
    </table>
  </div>
</div>

<!-- Backdrop -->
<div class="drawer-backdrop" id="backdrop"></div>

<!-- Device Inspector Drawer -->
<aside class="drawer" id="deviceDrawer" aria-hidden="true">
  <div class="drawer-head">
    <h2 id="drawerTitle">Device Inspector</h2>
    <button class="btn-chip" type="button" id="closeDeviceDrawer">Close</button>
  </div>
  <div class="drawer-body">
    <div class="meta-box" id="drawerMeta"></div>
    <div class="field-group">
      <label for="metaClientName">Client / Company Name</label>
      <input id="metaClientName" type="text" maxlength="80" placeholder="e.g. Clinic Alpha — Desk 2">
    </div>
    <div class="field-group">
      <label for="metaNotes">Operator Notes</label>
      <textarea id="metaNotes" rows="4" maxlength="500" placeholder="Hardware location, warranty notes, configuration..."></textarea>
    </div>
    <button class="btn btn-primary" type="button" id="saveMetaBtn" style="padding: 11px 16px; justify-content: center;">Save Client Details</button>
    <div style="border-top: 1px solid var(--border); padding-top: 14px; display: flex; flex-direction: column; gap: 10px;">
      <button class="btn btn-ghost" type="button" id="reenrollBtn" style="justify-content: center;">Allow One-Time Re-Enrollment</button>
      <button class="btn btn-danger" type="button" id="drawerDeleteBtn" style="justify-content: center;">Delete Device Record</button>
    </div>
  </div>
</aside>

<!-- Audit Log Drawer -->
<aside class="drawer" id="auditDrawer" aria-hidden="true">
  <div class="drawer-head">
    <h2>Security &amp; Support Audit Log</h2>
    <button class="btn-chip" type="button" id="closeAuditDrawer">Close</button>
  </div>
  <div class="drawer-body" id="auditList"></div>
</aside>

<!-- Custom Confirm Modal -->
<div class="modal" id="confirmModal" role="dialog" aria-modal="true">
  <h3 id="modalTitle">Confirm Action</h3>
  <p id="modalMsg"></p>
  <div class="modal-btns">
    <button class="btn btn-ghost" type="button" id="modalCancel">Cancel</button>
    <button class="btn btn-danger" type="button" id="modalConfirm">Confirm</button>
  </div>
</div>

<div class="toast-stack" id="toastStack"></div>

<script>
""" + CONSTELLATION_SCRIPT + """
(function() {
  const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content') || '';
  let fleetData = { clienti: {}, stats: { total: 0, online: 0, secure: 0, compromised: 0 }, audit_log: [] };
  let activeFilter = 'all';
  let searchQuery = '';
  let inspectedHwid = null;
  let pendingModalAction = null;
  const rejectedTimers = {};
  const displayedCounters = { total: 0, online: 0, secure: 0, compromised: 0 };

  function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showToast(msg) {
    const stack = document.getElementById('toastStack');
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(8px)';
      el.style.transition = 'opacity 0.2s, transform 0.2s';
      setTimeout(() => el.remove(), 220);
    }, 2600);
  }

  async function copyText(text, label, btnEl) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    if (btnEl) {
      btnEl.classList.add('copied-flash');
      setTimeout(() => btnEl.classList.remove('copied-flash'), 650);
    }
    showToast((label || 'Value') + ' copied to clipboard');
  }

  function animateCounter(elId, key, targetVal) {
    const el = document.getElementById(elId);
    if (!el) return;
    const startVal = displayedCounters[key] || 0;
    if (startVal === targetVal) { el.textContent = String(targetVal); return; }
    displayedCounters[key] = targetVal;
    const t0 = performance.now();
    const dur = 360;
    function step(now) {
      const p = Math.min(1, (now - t0) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = String(Math.round(startVal + (targetVal - startVal) * eased));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function formatRelative(ts) {
    if (!ts) return 'never';
    const diff = Math.max(0, Math.floor((Date.now() / 1000) - ts));
    if (diff < 5) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  async function postAdmin(url, bodyObj) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: bodyObj ? JSON.stringify(bodyObj) : '{}'
    });
    if (res.status === 401) { window.location.reload(); return null; }
    return res;
  }

  function openConfirm(title, message, onConfirm) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalMsg').textContent = message;
    pendingModalAction = onConfirm;
    document.getElementById('backdrop').classList.add('open');
    document.getElementById('confirmModal').classList.add('open');
  }

  function closeAllOverlays() {
    document.getElementById('backdrop').classList.remove('open');
    document.getElementById('deviceDrawer').classList.remove('open');
    document.getElementById('auditDrawer').classList.remove('open');
    document.getElementById('confirmModal').classList.remove('open');
    pendingModalAction = null;
  }

  function openDeviceDrawer(hwid) {
    const info = fleetData.clienti[hwid];
    if (!info) return;
    inspectedHwid = hwid;
    document.getElementById('drawerTitle').textContent = info.client_name || info.hostname || hwid;
    document.getElementById('metaClientName').value = info.client_name || '';
    document.getElementById('metaNotes').value = info.notes || '';
    renderDrawerMeta(hwid, info);
    document.getElementById('backdrop').classList.add('open');
    document.getElementById('auditDrawer').classList.remove('open');
    document.getElementById('deviceDrawer').classList.add('open');
  }

  function renderDrawerMeta(hwid, info) {
    const box = document.getElementById('drawerMeta');
    if (!box || !info) return;
    box.innerHTML = `
      <span class="mk">HWID</span><span class="mv">${escapeHtml(hwid)}</span>
      <span class="mk">Hostname</span><span class="mv">${escapeHtml(info.hostname || '—')}</span>
      <span class="mk">IP Address</span><span class="mv">${escapeHtml(info.ip || '—')}</span>
      <span class="mk">Presence</span><span class="mv">${info.online ? 'Online' : 'Offline'} (${formatRelative(info.last_seen_ts)})</span>
      <span class="mk">Integrity</span><span class="mv">${escapeHtml(info.status || 'Unknown')}</span>
      <span class="mk">Re-enroll</span><span class="mv">${info.allow_reenroll ? 'Approved (Waiting)' : 'Locked'}</span>
    `;
  }

  function renderAuditDrawer() {
    const list = document.getElementById('auditList');
    const items = fleetData.audit_log || [];
    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No audit events recorded yet.</div>';
      return;
    }
    list.innerHTML = items.map(ev => `
      <div class="audit-item sev-${escapeHtml(ev.severity || 'info')}">
        <div class="audit-top">
          <strong>${escapeHtml(ev.hostname || 'System')} • ${escapeHtml(ev.type || 'event')}</strong>
          <span>${escapeHtml(ev.time || '')}</span>
        </div>
        <div class="audit-msg">${escapeHtml(ev.detail || '')}</div>
      </div>
    `).join('');
  }

  function matchesFilter(hwid, info) {
    if (activeFilter === 'online' && !info.online) return false;
    if (activeFilter === 'offline' && info.online) return false;
    if (activeFilter === 'modified' && info.status === 'Integru') return false;
    if (activeFilter === 'support' && info.support_state !== 'waiting' && info.support_state !== 'approved') return false;
    if (searchQuery) {
      const hay = [hwid, info.client_name, info.hostname, info.ip, info.notes, info.status]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  }

  function renderTable() {
    const tbody = document.getElementById('clients-tbody');
    const entries = Object.entries(fleetData.clienti || {});
    entries.sort((a, b) => {
      if (!!b[1].online !== !!a[1].online) return b[1].online ? 1 : -1;
      return (b[1].last_seen_ts || 0) - (a[1].last_seen_ts || 0);
    });

    const filtered = entries.filter(([hwid, info]) => matchesFilter(hwid, info));
    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">${entries.length ? 'No MiniPCs match your active search/filter.' : 'No enrolled SourceLess MiniPCs yet.'}</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(([hwid, info]) => {
      const safeHwid = escapeHtml(hwid);
      const isOnline = !!info.online;
      const isSecure = info.status === 'Integru';
      const displayName = info.client_name || info.hostname || 'Unassigned Device';
      const subHost = info.client_name && info.hostname ? info.hostname : (info.notes ? info.notes.slice(0, 42) : 'Standard Node');

      const presenceHtml = isOnline
        ? '<span class="presence on"><span class="radar-dot"></span>Online</span>'
        : '<span class="presence off"><span class="radar-dot"></span>Offline</span>';

      const statusHtml = isSecure
        ? '<span class="badge badge-secure">Secure</span>'
        : '<span class="badge badge-alert">' + escapeHtml(info.status || 'Modified') + '</span>';

      let credsHtml = '<span style="color: var(--muted);">—</span>';
      if (info.support_state === 'approved' && info.rustdesk_id && info.rustdesk_id !== 'N/A') {
        credsHtml = `
          <button class="cred-chip" type="button" data-copy="${escapeHtml(info.rustdesk_id)}" data-label="RustDesk ID">ID: ${escapeHtml(info.rustdesk_id)}</button>
          <button class="cred-chip" type="button" data-copy="${escapeHtml(info.rustdesk_pw)}" data-label="RustDesk Password">PW: ${escapeHtml(info.rustdesk_pw)}</button>
        `;
      } else if (info.support_state === 'rejected') {
        credsHtml = '<span class="badge badge-alert">Access Denied</span>';
      } else if (info.support_state === 'waiting') {
        credsHtml = '<span class="badge badge-waiting"><span class="spin-ring"></span>Waiting Approval</span>';
      }

      let btns = '';
      if (!isSecure) {
        btns += `<button class="btn btn-primary" type="button" data-action="reinstate" data-hwid="${safeHwid}">Reinstate</button>`;
      }
      if (info.support_state === 'waiting') {
        btns += `<button class="btn btn-danger" type="button" data-action="stop_support" data-hwid="${safeHwid}">Cancel</button>`;
      } else if (info.support_state === 'approved') {
        btns += `<button class="btn btn-danger" type="button" data-action="stop_support" data-hwid="${safeHwid}">Stop Support</button>`;
      } else {
        btns += `<button class="btn btn-support" type="button" data-action="request_support" data-hwid="${safeHwid}" ${isOnline ? '' : 'disabled title="Device is offline"'}>Request Access</button>`;
      }
      btns += `<button class="btn btn-ghost" type="button" data-action="inspect" data-hwid="${safeHwid}">Details</button>`;

      return `
        <tr data-hwid="${safeHwid}">
          <td>${presenceHtml}</td>
          <td>
            <div class="device-cell">
              <span class="client-name">${escapeHtml(displayName)}</span>
              <span class="host-sub">${escapeHtml(subHost)}</span>
            </div>
          </td>
          <td>
            <button class="hwid-btn" type="button" data-copy="${safeHwid}" data-label="HWID" title="Click to copy ${safeHwid}">
              <span class="hwid-txt">${safeHwid}</span>
            </button>
          </td>
          <td>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;">${escapeHtml(info.ip || '—')}</div>
            <div style="font-size: 0.75rem; color: var(--muted);" title="${escapeHtml(info.last_seen || '')}">${formatRelative(info.last_seen_ts)}</div>
          </td>
          <td>${statusHtml}</td>
          <td>${credsHtml}</td>
          <td><div class="actions-row">${btns}</div></td>
        </tr>
      `;
    }).join('');
  }

  async function refreshDashboard() {
    try {
      const res = await fetch('/api/data', { headers: { 'Accept': 'application/json' } });
      if (res.status === 401) { window.location.reload(); return; }
      const data = await res.json();
      fleetData = data;

      for (const [hwid, info] of Object.entries(data.clienti || {})) {
        if (info.support_state === 'rejected') {
          if (!rejectedTimers[hwid]) {
            rejectedTimers[hwid] = setTimeout(async () => {
              await postAdmin('/stop_support/' + encodeURIComponent(hwid));
              delete rejectedTimers[hwid];
              refreshDashboard();
            }, 10000);
          }
        } else if (rejectedTimers[hwid]) {
          clearTimeout(rejectedTimers[hwid]);
          delete rejectedTimers[hwid];
        }
      }

      const st = data.stats || {};
      animateCounter('stat-total', 'total', st.total || 0);
      animateCounter('stat-online', 'online', st.online || 0);
      animateCounter('stat-secure', 'secure', st.secure || 0);
      animateCounter('stat-compromised', 'compromised', st.compromised || 0);

      renderTable();
      if (inspectedHwid && data.clienti[inspectedHwid] && document.getElementById('deviceDrawer').classList.contains('open')) {
        renderDrawerMeta(inspectedHwid, data.clienti[inspectedHwid]);
      }
      if (document.getElementById('auditDrawer').classList.contains('open')) {
        renderAuditDrawer();
      }
    } catch (err) {
      console.error('Telemetry refresh failed:', err);
    }
  }

  // Cursor spotlight on KPI cards
  document.querySelectorAll('.kpi-card').forEach(card => {
    card.addEventListener('pointermove', (e) => {
      const r = card.getBoundingClientRect();
      card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
      card.style.setProperty('--my', (e.clientY - r.top) + 'px');
    }, { passive: true });
  });

  // Topbar actions
  document.getElementById('copyKeyBtn').addEventListener('click', (e) => {
    copyText(document.getElementById('supportKeyVal').textContent.trim(), 'Support Key', e.currentTarget);
  });
  document.getElementById('openAuditBtn').addEventListener('click', () => {
    renderAuditDrawer();
    document.getElementById('backdrop').classList.add('open');
    document.getElementById('deviceDrawer').classList.remove('open');
    document.getElementById('auditDrawer').classList.add('open');
  });

  // Search & filter pills
  document.getElementById('searchInput').addEventListener('input', (e) => {
    searchQuery = e.target.value.trim().toLowerCase();
    renderTable();
  });
  document.getElementById('filterPills').addEventListener('click', (e) => {
    const pill = e.target.closest('.filter-pill');
    if (!pill) return;
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    activeFilter = pill.getAttribute('data-filter') || 'all';
    renderTable();
  });

  // Table event delegation (Copy + Actions)
  document.getElementById('clients-tbody').addEventListener('click', async (e) => {
    const copyBtn = e.target.closest('[data-copy]');
    if (copyBtn) {
      copyText(copyBtn.getAttribute('data-copy'), copyBtn.getAttribute('data-label'), copyBtn);
      return;
    }
    const actBtn = e.target.closest('[data-action]');
    if (!actBtn) return;
    const action = actBtn.getAttribute('data-action');
    const hwid = actBtn.getAttribute('data-hwid');
    if (!hwid) return;

    if (action === 'inspect') {
      openDeviceDrawer(hwid);
    } else if (action === 'reinstate' || action === 'request_support' || action === 'stop_support') {
      await postAdmin('/' + action + '/' + encodeURIComponent(hwid));
      showToast(action === 'reinstate' ? 'Tamper seal reinstated' : (action === 'request_support' ? 'Support prompt dispatched' : 'Support session stopped'));
      refreshDashboard();
    }
  });

  // Drawer & Modal buttons
  document.getElementById('backdrop').addEventListener('click', closeAllOverlays);
  document.getElementById('closeDeviceDrawer').addEventListener('click', closeAllOverlays);
  document.getElementById('closeAuditDrawer').addEventListener('click', closeAllOverlays);
  document.getElementById('modalCancel').addEventListener('click', closeAllOverlays);
  document.getElementById('modalConfirm').addEventListener('click', async () => {
    if (pendingModalAction) await pendingModalAction();
    closeAllOverlays();
  });

  document.getElementById('saveMetaBtn').addEventListener('click', async () => {
    if (!inspectedHwid) return;
    const clientName = document.getElementById('metaClientName').value.trim();
    const notes = document.getElementById('metaNotes').value.trim();
    const res = await postAdmin('/update_meta/' + encodeURIComponent(inspectedHwid), { client_name: clientName, notes });
    if (res && res.ok) {
      showToast('Client details saved');
      refreshDashboard();
    }
  });

  document.getElementById('reenrollBtn').addEventListener('click', () => {
    if (!inspectedHwid) return;
    const targetHwid = inspectedHwid;
    openConfirm(
      'Approve One-Time Re-Enrollment?',
      'This allows device ' + targetHwid + ' to re-register and receive a new certificate/token on its next boot or OS reinstall.',
      async () => {
        await postAdmin('/allow_reenroll/' + encodeURIComponent(targetHwid));
        showToast('Re-enrollment approved for next device check-in');
        refreshDashboard();
      }
    );
  });

  document.getElementById('drawerDeleteBtn').addEventListener('click', () => {
    if (!inspectedHwid) return;
    const targetHwid = inspectedHwid;
    openConfirm(
      'Delete Device Record?',
      'Remove HWID ' + targetHwid + ' from the fleet database? It will lose telemetry access until re-enrolled.',
      async () => {
        await postAdmin('/delete_client/' + encodeURIComponent(targetHwid));
        inspectedHwid = null;
        showToast('Device deleted');
        refreshDashboard();
      }
    );
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllOverlays();
  });

  setInterval(refreshDashboard, 2000);
  refreshDashboard();
})();
</script>
</body>
</html>
"""


# --- ROUTES ---
@app.route("/login")
def legacy_login():
    abort(404)


@app.route(LOGIN_GATE_ROUTE, methods=["GET", "POST"])
def login():
    client_ip = get_client_ip()
    csrf_token = get_csrf_token()

    if is_ip_blocked(client_ip):
        return render_template_string(
            LOGIN_TEMPLATE,
            error="Too many failed attempts. Temporarily locked out.",
            csrf_token=csrf_token,
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

    return render_template_string(LOGIN_TEMPLATE, error=error, csrf_token=csrf_token)


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
    return render_template_string(
        DASHBOARD_TEMPLATE,
        support_key=get_today_support_key(),
        csrf_token=get_csrf_token(),
    )


@app.route("/api/data")
@login_required
def api_data():
    now_ts = time.time()
    public_clients = {}
    online_count = 0
    secure_count = 0

    with DB_LOCK:
        for hwid, info in db_clienti.items():
            seen_ts = compute_last_seen_ts(info)
            is_online = seen_ts > 0 and (now_ts - seen_ts) <= ONLINE_THRESHOLD_SECONDS
            if is_online:
                online_count += 1
            if info.get("status") == "Integru":
                secure_count += 1

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
        }
        recent_audit = list(audit_log[:40])

    return jsonify({"clienti": public_clients, "stats": stats, "audit_log": recent_audit})


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
            append_audit("tamper_detected", hwid, hostname, client_ip, f"System integrity changed: {prev_status} -> {status}", "critical")
        elif prev_status and prev_status != "Integru" and status == "Integru":
            append_audit("status_restored", hwid, hostname, client_ip, "System integrity verified as Integru", "ok")

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
            "token": expected_token,
        }
        save_db()

    return jsonify({"message": "Status received", "command": command}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
