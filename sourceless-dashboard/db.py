from contextlib import contextmanager
import json
import os
import sqlite3
import threading
import time
import uuid

CLIENT_COLUMNS = frozenset(
    {
        "hostname",
        "client_name",
        "organization",
        "notes",
        "ip",
        "status",
        "last_seen",
        "last_seen_ts",
        "pending_reinstate",
        "rustdesk_id",
        "rustdesk_pw",
        "support_state",
        "support_updated_ts",
        "pending_cmd",
        "allow_reenroll",
        "revoked",
        "os_version",
        "update_channel",
        "update_status",
        "selinux",
        "lockdown",
        "yara_active",
        "ram_percent",
        "disk_percent",
        "uptime",
        "token",
    }
)

CLIENT_BOOL_COLUMNS = frozenset(
    {"pending_reinstate", "allow_reenroll", "revoked", "yara_active"}
)

USER_COLUMNS = frozenset(
    {
        "full_name",
        "role",
        "password_hash",
        "active",
        "protected",
        "created_at",
        "created_by",
        "last_login",
    }
)

USER_BOOL_COLUMNS = frozenset({"active", "protected"})


def _load_json_safe(filepath, expected_type):
    if not filepath or not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, expected_type):
            return data
    except Exception:
        return None
    return None


def _to_int_flag(val, default=0):
    if val is None:
        return default
    return 1 if bool(val) else 0


def _to_nullable_int(val):
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _escape_like(term):
    return (
        term.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


class DashboardStore:
    """Thread-safe and multi-worker-safe SQLite (WAL) store for SourceLess Fleet Console."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "sourceless.db")
        self._lock = threading.RLock()
        self._shared_conn = None
        self._tx_depth = 0
        self.init_schema()

    def _conn(self):
        with self._lock:
            if self._shared_conn is None:
                conn = sqlite3.connect(
                    self.db_path,
                    timeout=15.0,
                    isolation_level=None,
                    check_same_thread=False,
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("PRAGMA busy_timeout=15000;")
                conn.execute("PRAGMA cache_size=-4000;")
                conn.execute("PRAGMA temp_store=MEMORY;")
                self._shared_conn = conn
                self._tx_depth = 0
            return self._shared_conn

    def close(self):
        with self._lock:
            if self._shared_conn is not None:
                try:
                    self._shared_conn.close()
                except sqlite3.Error:
                    pass
                self._shared_conn = None
                self._tx_depth = 0

    close_thread_connection = close

    @contextmanager
    def write_tx(self):
        with self._lock:
            conn = self._conn()
            depth = self._tx_depth
            if depth == 0:
                conn.execute("BEGIN IMMEDIATE;")
            self._tx_depth = depth + 1
            try:
                yield conn
            except BaseException:
                self._tx_depth = depth
                if depth == 0 and conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK;")
                    except sqlite3.Error:
                        pass
                raise
            else:
                self._tx_depth = depth
                if depth == 0 and conn.in_transaction:
                    conn.execute("COMMIT;")

    def get_journal_mode(self):
        with self._lock:
            row = self._conn().execute("PRAGMA journal_mode;").fetchone()
            return str(row[0]).lower() if row else ""

    def init_schema(self):
        with self._lock:
            conn = self._conn()
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS clients (
                    hwid TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL DEFAULT '',
                    client_name TEXT NOT NULL DEFAULT '',
                    organization TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    ip TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'Inscris',
                    last_seen TEXT NOT NULL DEFAULT '',
                    last_seen_ts REAL NOT NULL DEFAULT 0.0,
                    pending_reinstate INTEGER NOT NULL DEFAULT 0,
                    rustdesk_id TEXT NOT NULL DEFAULT 'N/A',
                    rustdesk_pw TEXT NOT NULL DEFAULT 'N/A',
                    support_state TEXT NOT NULL DEFAULT 'idle',
                    support_updated_ts REAL NOT NULL DEFAULT 0.0,
                    pending_cmd TEXT NOT NULL DEFAULT '',
                    allow_reenroll INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    os_version TEXT NOT NULL DEFAULT '',
                    update_channel TEXT NOT NULL DEFAULT 'stable',
                    update_status TEXT NOT NULL DEFAULT '',
                    selinux TEXT NOT NULL DEFAULT '',
                    lockdown TEXT NOT NULL DEFAULT '',
                    yara_active INTEGER NOT NULL DEFAULT 1,
                    ram_percent INTEGER,
                    disk_percent INTEGER,
                    uptime TEXT NOT NULL DEFAULT '',
                    token TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_clients_last_seen_ts ON clients(last_seen_ts);
                CREATE INDEX IF NOT EXISTS idx_clients_support_state ON clients(support_state);

                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'support',
                    password_hash TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    protected INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT 'system',
                    last_login TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL,
                    time TEXT NOT NULL,
                    ts REAL NOT NULL,
                    actor TEXT NOT NULL,
                    actor_name TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    category TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    hwid TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    client_label TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC, seq DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_hwid ON audit_log(hwid, seq DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
                CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category);
                CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);

                CREATE TABLE IF NOT EXISTS yara_alerts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL,
                    time TEXT NOT NULL,
                    ts REAL NOT NULL,
                    hwid TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    client_label TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_yara_seq ON yara_alerts(seq DESC);

                CREATE TABLE IF NOT EXISTS login_attempts (
                    ip TEXT PRIMARY KEY,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    blocked_until REAL NOT NULL DEFAULT 0.0
                );
                """
            )
            cols = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(clients);").fetchall()
            }
            if "organization" not in cols:
                conn.execute(
                    "ALTER TABLE clients ADD COLUMN organization TEXT NOT NULL DEFAULT '';"
                )

    def migrate_legacy_json(self, legacy_paths, timestamp_str):
        """One-time idempotent import from legacy JSON files into SQLite."""
        migrated_files = []
        with self.write_tx() as conn:
            clients_path = legacy_paths.get("clients")
            clients_count = conn.execute("SELECT COUNT(*) FROM clients;").fetchone()[0]
            if clients_count == 0:
                legacy_clients = _load_json_safe(clients_path, dict)
                if legacy_clients is not None:
                    for hwid, rec in legacy_clients.items():
                        if isinstance(rec, dict) and hwid:
                            self.upsert_client(hwid, rec)
                    migrated_files.append(clients_path)

            users_path = legacy_paths.get("users")
            users_count = conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
            if users_count == 0:
                legacy_users = _load_json_safe(users_path, dict)
                if legacy_users is not None:
                    for uname, rec in legacy_users.items():
                        if isinstance(rec, dict) and uname:
                            user_copy = dict(rec)
                            user_copy.setdefault("username", uname)
                            self.upsert_user(user_copy)
                    migrated_files.append(users_path)

            audit_path = legacy_paths.get("audit")
            audit_count = conn.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0]
            if audit_count == 0:
                legacy_audit = _load_json_safe(audit_path, list)
                if legacy_audit is not None:
                    for rec in reversed(legacy_audit):
                        if isinstance(rec, dict):
                            self.insert_audit(rec, trim=False)
                    migrated_files.append(audit_path)

            yara_path = legacy_paths.get("yara")
            yara_count = conn.execute("SELECT COUNT(*) FROM yara_alerts;").fetchone()[0]
            if yara_count == 0:
                legacy_yara = _load_json_safe(yara_path, list)
                if legacy_yara is not None:
                    for rec in reversed(legacy_yara):
                        if isinstance(rec, dict):
                            self.insert_yara_alert(rec, max_entries=None)
                    migrated_files.append(yara_path)

            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?);",
                ("schema_version", "1"),
            )
            if migrated_files:
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?);",
                    ("json_migrated_at", str(timestamp_str)),
                )

        for fpath in migrated_files:
            backup_path = f"{fpath}.migrated.bak"
            if os.path.exists(backup_path):
                backup_path = f"{fpath}.{int(time.time())}.migrated.bak"
            try:
                os.replace(fpath, backup_path)
            except OSError:
                pass
        return len(migrated_files)

    def get_or_create_secret(self, key, generator_fn):
        with self.write_tx() as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = ?;", (key,)
            ).fetchone()
            if row and row["value"]:
                return row["value"]
            val = generator_fn()
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?);",
                (key, val),
            )
            return val

    # --- CLIENTS ---
    @staticmethod
    def _row_to_client(row):
        return {
            "hostname": row["hostname"],
            "client_name": row["client_name"],
            "organization": row["organization"],
            "notes": row["notes"],
            "ip": row["ip"],
            "status": row["status"],
            "last_seen": row["last_seen"],
            "last_seen_ts": float(row["last_seen_ts"] or 0.0),
            "pending_reinstate": bool(row["pending_reinstate"]),
            "rustdesk_id": row["rustdesk_id"],
            "rustdesk_pw": row["rustdesk_pw"],
            "support_state": row["support_state"],
            "support_updated_ts": float(row["support_updated_ts"] or 0.0),
            "pending_cmd": row["pending_cmd"],
            "allow_reenroll": bool(row["allow_reenroll"]),
            "revoked": bool(row["revoked"]),
            "os_version": row["os_version"],
            "update_channel": row["update_channel"],
            "update_status": row["update_status"],
            "selinux": row["selinux"],
            "lockdown": row["lockdown"],
            "yara_active": bool(row["yara_active"]),
            "ram_percent": row["ram_percent"],
            "disk_percent": row["disk_percent"],
            "uptime": row["uptime"],
            "token": row["token"],
        }

    def get_client(self, hwid):
        if not hwid:
            return None
        with self._lock:
            row = (
                self._conn()
                .execute("SELECT * FROM clients WHERE hwid = ?;", (hwid,))
                .fetchone()
            )
            return self._row_to_client(row) if row else None

    def list_clients(self):
        with self._lock:
            rows = self._conn().execute("SELECT * FROM clients;").fetchall()
            return {row["hwid"]: self._row_to_client(row) for row in rows}

    def upsert_client(self, hwid, data):
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO clients (
                    hwid, hostname, client_name, organization, notes, ip, status,
                    last_seen, last_seen_ts, pending_reinstate, rustdesk_id, rustdesk_pw,
                    support_state, support_updated_ts, pending_cmd, allow_reenroll, revoked,
                    os_version, update_channel, update_status, selinux, lockdown,
                    yara_active, ram_percent, disk_percent, uptime, token
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                ON CONFLICT(hwid) DO UPDATE SET
                    hostname = excluded.hostname,
                    client_name = excluded.client_name,
                    organization = excluded.organization,
                    notes = excluded.notes,
                    ip = excluded.ip,
                    status = excluded.status,
                    last_seen = excluded.last_seen,
                    last_seen_ts = excluded.last_seen_ts,
                    pending_reinstate = excluded.pending_reinstate,
                    rustdesk_id = excluded.rustdesk_id,
                    rustdesk_pw = excluded.rustdesk_pw,
                    support_state = excluded.support_state,
                    support_updated_ts = excluded.support_updated_ts,
                    pending_cmd = excluded.pending_cmd,
                    allow_reenroll = excluded.allow_reenroll,
                    revoked = excluded.revoked,
                    os_version = excluded.os_version,
                    update_channel = excluded.update_channel,
                    update_status = excluded.update_status,
                    selinux = excluded.selinux,
                    lockdown = excluded.lockdown,
                    yara_active = excluded.yara_active,
                    ram_percent = excluded.ram_percent,
                    disk_percent = excluded.disk_percent,
                    uptime = excluded.uptime,
                    token = excluded.token;
                """,
                (
                    hwid,
                    str(data.get("hostname", "")),
                    str(data.get("client_name", "")),
                    str(data.get("organization", "")),
                    str(data.get("notes", "")),
                    str(data.get("ip", "")),
                    str(data.get("status", "Inscris")),
                    str(data.get("last_seen", "")),
                    float(data.get("last_seen_ts") or 0.0),
                    _to_int_flag(data.get("pending_reinstate"), 0),
                    str(data.get("rustdesk_id", "N/A") or "N/A"),
                    str(data.get("rustdesk_pw", "N/A") or "N/A"),
                    str(data.get("support_state", "idle") or "idle"),
                    float(data.get("support_updated_ts") or 0.0),
                    str(data.get("pending_cmd", "")),
                    _to_int_flag(data.get("allow_reenroll"), 0),
                    _to_int_flag(data.get("revoked"), 0),
                    str(data.get("os_version", "")),
                    str(data.get("update_channel", "stable") or "stable"),
                    str(data.get("update_status", "")),
                    str(data.get("selinux", "")),
                    str(data.get("lockdown", "")),
                    _to_int_flag(data.get("yara_active", True), 1),
                    _to_nullable_int(data.get("ram_percent")),
                    _to_nullable_int(data.get("disk_percent")),
                    str(data.get("uptime", "")),
                    str(data.get("token", "")),
                ),
            )

    def update_client_fields(self, hwid, **fields):
        if not hwid or not fields:
            return False
        assignments = []
        values = []
        for col, val in fields.items():
            if col not in CLIENT_COLUMNS:
                raise ValueError(f"Unsupported client column: {col}")
            assignments.append(f"{col} = ?")
            if col in CLIENT_BOOL_COLUMNS:
                values.append(_to_int_flag(val))
            elif col in ("ram_percent", "disk_percent"):
                values.append(_to_nullable_int(val))
            elif col in ("last_seen_ts", "support_updated_ts"):
                values.append(float(val or 0.0))
            else:
                values.append("" if val is None else str(val))
        values.append(hwid)
        sql = f"UPDATE clients SET {', '.join(assignments)} WHERE hwid = ?;"
        with self.write_tx() as conn:
            cur = conn.execute(sql, values)
            return cur.rowcount > 0

    def delete_client(self, hwid):
        with self.write_tx() as conn:
            row = conn.execute(
                "SELECT * FROM clients WHERE hwid = ?;", (hwid,)
            ).fetchone()
            if not row:
                return None
            removed = self._row_to_client(row)
            conn.execute("DELETE FROM clients WHERE hwid = ?;", (hwid,))
            return removed

    # --- USERS ---
    @staticmethod
    def _row_to_user(row):
        return {
            "username": row["username"],
            "full_name": row["full_name"],
            "role": row["role"],
            "password_hash": row["password_hash"],
            "active": bool(row["active"]),
            "protected": bool(row["protected"]),
            "created_at": row["created_at"],
            "created_by": row["created_by"],
            "last_login": row["last_login"],
        }

    def get_user(self, username):
        if not username:
            return None
        with self._lock:
            row = (
                self._conn()
                .execute("SELECT * FROM users WHERE username = ?;", (username,))
                .fetchone()
            )
            return self._row_to_user(row) if row else None

    def list_users(self):
        with self._lock:
            rows = self._conn().execute("SELECT * FROM users;").fetchall()
            return [self._row_to_user(row) for row in rows]

    def upsert_user(self, data):
        username = str(data.get("username", "")).strip()
        if not username:
            raise ValueError("Username is required.")
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    username, full_name, role, password_hash, active,
                    protected, created_at, created_by, last_login
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    full_name = excluded.full_name,
                    role = excluded.role,
                    password_hash = excluded.password_hash,
                    active = excluded.active,
                    protected = excluded.protected,
                    created_at = excluded.created_at,
                    created_by = excluded.created_by,
                    last_login = excluded.last_login;
                """,
                (
                    username,
                    str(data.get("full_name", "")),
                    str(data.get("role", "support") or "support"),
                    str(data.get("password_hash", "")),
                    _to_int_flag(data.get("active", True), 1),
                    _to_int_flag(data.get("protected", False), 0),
                    str(data.get("created_at", "")),
                    str(data.get("created_by", "system") or "system"),
                    str(data.get("last_login", "")),
                ),
            )

    def update_user_fields(self, username, **fields):
        if not username or not fields:
            return False
        assignments = []
        values = []
        for col, val in fields.items():
            if col not in USER_COLUMNS:
                raise ValueError(f"Unsupported user column: {col}")
            assignments.append(f"{col} = ?")
            if col in USER_BOOL_COLUMNS:
                values.append(_to_int_flag(val))
            else:
                values.append("" if val is None else str(val))
        values.append(username)
        sql = f"UPDATE users SET {', '.join(assignments)} WHERE username = ?;"
        with self.write_tx() as conn:
            cur = conn.execute(sql, values)
            return cur.rowcount > 0

    def delete_user(self, username):
        with self.write_tx() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?;", (username,))
            return cur.rowcount > 0

    # --- AUDIT LOG ---
    @staticmethod
    def _row_to_audit(row):
        return {
            "id": row["id"],
            "time": row["time"],
            "ts": float(row["ts"] or 0.0),
            "actor": row["actor"] or "SYSTEM",
            "actor_name": row["actor_name"] or row["actor"] or "SYSTEM",
            "actor_role": row["actor_role"] or "system",
            "category": row["category"] or "system",
            "type": row["type"] or "event",
            "severity": row["severity"] or "info",
            "hwid": row["hwid"] or "SYSTEM",
            "hostname": row["hostname"] or "Console",
            "client_label": row["client_label"] or row["hostname"] or row["hwid"] or "System",
            "ip": row["ip"] or "127.0.0.1",
            "detail": row["detail"] or "",
            "reason": row["reason"] or "",
        }

    def insert_audit(self, entry, trim=True, max_entries=100000):
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (
                    id, time, ts, actor, actor_name, actor_role, category,
                    type, severity, hwid, hostname, client_label, ip, detail, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(entry.get("id") or uuid.uuid4().hex[:10]),
                    str(entry.get("time", "")),
                    float(entry.get("ts") or time.time()),
                    str(entry.get("actor") or "SYSTEM"),
                    str(entry.get("actor_name") or entry.get("actor") or "SYSTEM"),
                    str(entry.get("actor_role") or "system"),
                    str(entry.get("category") or "system"),
                    str(entry.get("type") or "event"),
                    str(entry.get("severity") or "info"),
                    str(entry.get("hwid") or "SYSTEM"),
                    str(entry.get("hostname") or "Console"),
                    str(
                        entry.get("client_label")
                        or entry.get("hostname")
                        or entry.get("hwid")
                        or "System"
                    ),
                    str(entry.get("ip") or "127.0.0.1"),
                    str(entry.get("detail") or ""),
                    str(entry.get("reason") or "").strip(),
                ),
            )
            if trim and max_entries:
                conn.execute(
                    """
                    DELETE FROM audit_log
                    WHERE seq <= (
                        SELECT seq FROM audit_log ORDER BY seq DESC LIMIT 1 OFFSET ?
                    );
                    """,
                    (int(max_entries),),
                )

    def query_audit(
        self,
        q="",
        actor="",
        category="",
        severity="",
        hwid="",
        days_raw="",
        limit=250,
    ):
        q = (q or "").strip().lower()
        actor = (actor or "").strip()
        category = (category or "").strip().lower()
        severity = (severity or "").strip().lower()
        hwid = (hwid or "").strip()
        days_raw = (days_raw or "").strip()

        try:
            limit_val = max(1, min(5000, int(limit)))
        except (TypeError, ValueError):
            limit_val = 250

        clauses = []
        params = []

        if days_raw:
            try:
                days_val = float(days_raw)
                if days_val > 0:
                    clauses.append("ts >= ?")
                    params.append(time.time() - (days_val * 86400.0))
            except ValueError:
                pass

        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if category:
            clauses.append("LOWER(category) = ?")
            params.append(category)
        if severity:
            clauses.append("LOWER(severity) = ?")
            params.append(severity)
        if hwid:
            clauses.append("hwid = ?")
            params.append(hwid)
        if q:
            like_pat = f"%{_escape_like(q)}%"
            cols = (
                "actor",
                "actor_name",
                "type",
                "category",
                "hwid",
                "hostname",
                "client_label",
                "ip",
                "detail",
                "reason",
            )
            sub = " OR ".join(f"LOWER({c}) LIKE ? ESCAPE '\\'" for c in cols)
            clauses.append(f"({sub})")
            params.extend([like_pat] * len(cols))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM audit_log {where_sql} "
            "ORDER BY ts DESC, seq DESC LIMIT ?;"
        )
        params.append(limit_val)

        with self._lock:
            conn = self._conn()
            rows = conn.execute(sql, params).fetchall()
            actor_rows = conn.execute(
                "SELECT DISTINCT actor FROM audit_log WHERE actor != '' ORDER BY actor ASC;"
            ).fetchall()

        results = [self._row_to_audit(row) for row in rows]
        actors = [str(row["actor"]) for row in actor_rows]
        return results, actors

    # --- YARA ALERTS ---
    @staticmethod
    def _row_to_yara(row):
        return {
            "id": row["id"],
            "time": row["time"],
            "ts": float(row["ts"] or 0.0),
            "hwid": row["hwid"],
            "hostname": row["hostname"],
            "client_label": row["client_label"],
            "filename": row["filename"],
            "rule": row["rule"],
            "path": row["path"],
            "quarantine_path": row["quarantine_path"],
        }

    def insert_yara_alert(self, entry, max_entries=2000):
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO yara_alerts (
                    id, time, ts, hwid, hostname, client_label,
                    filename, rule, path, quarantine_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(entry.get("id") or uuid.uuid4().hex[:10]),
                    str(entry.get("time", "")),
                    float(entry.get("ts") or time.time()),
                    str(entry.get("hwid") or ""),
                    str(entry.get("hostname") or "Unknown"),
                    str(
                        entry.get("client_label")
                        or entry.get("hostname")
                        or entry.get("hwid")
                        or "Unknown"
                    ),
                    str(entry.get("filename") or "unknown"),
                    str(entry.get("rule") or "UnknownRule"),
                    str(entry.get("path") or ""),
                    str(entry.get("quarantine_path") or ""),
                ),
            )
            if max_entries:
                conn.execute(
                    """
                    DELETE FROM yara_alerts
                    WHERE seq <= (
                        SELECT seq FROM yara_alerts ORDER BY seq DESC LIMIT 1 OFFSET ?
                    );
                    """,
                    (int(max_entries),),
                )

    def list_yara_alerts(self, limit=60):
        with self._lock:
            rows = (
                self._conn()
                .execute(
                    "SELECT * FROM yara_alerts ORDER BY ts DESC, seq DESC LIMIT ?;",
                    (max(1, int(limit)),),
                )
                .fetchall()
            )
            return [self._row_to_yara(row) for row in rows]

    def count_yara_alerts(self):
        with self._lock:
            row = self._conn().execute("SELECT COUNT(*) FROM yara_alerts;").fetchone()
            return int(row[0]) if row else 0

    def clear_yara_alerts(self):
        with self.write_tx() as conn:
            cur = conn.execute("DELETE FROM yara_alerts;")
            return int(cur.rowcount or 0)

    # --- RATE LIMITING ---
    def is_ip_blocked(self, ip, max_attempts=5):
        now = time.time()
        with self.write_tx() as conn:
            row = conn.execute(
                "SELECT attempts, blocked_until FROM login_attempts WHERE ip = ?;",
                (ip,),
            ).fetchone()
            if not row:
                return False
            blocked_until = float(row["blocked_until"] or 0.0)
            attempts = int(row["attempts"] or 0)
            if blocked_until > now:
                return True
            if blocked_until <= now and attempts >= max_attempts:
                conn.execute("DELETE FROM login_attempts WHERE ip = ?;", (ip,))
            return False

    def record_failed_attempt(self, ip, max_attempts=5, lockout_seconds=900):
        now = time.time()
        with self.write_tx() as conn:
            row = conn.execute(
                "SELECT attempts FROM login_attempts WHERE ip = ?;", (ip,)
            ).fetchone()
            attempts = (int(row["attempts"]) if row else 0) + 1
            blocked_until = (now + lockout_seconds) if attempts >= max_attempts else 0.0
            conn.execute(
                """
                INSERT INTO login_attempts(ip, attempts, blocked_until)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    attempts = excluded.attempts,
                    blocked_until = excluded.blocked_until;
                """,
                (ip, attempts, blocked_until),
            )

    def reset_failed_attempts(self, ip):
        with self.write_tx() as conn:
            conn.execute("DELETE FROM login_attempts WHERE ip = ?;", (ip,))
