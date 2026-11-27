import json
import threading
import time

try:
    import redis as _redis_pkg
except ImportError:
    _redis_pkg = None


def _parse_int_or_none(raw):
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_float(raw, default=0.0):
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


class FleetRedisCache:
    """Optional Redis backend for fast heartbeat buffering, DB sync throttling, and shared fleet caching."""

    def __init__(self, redis_url=None, heartbeat_ttl=300, pgsync_ttl=300, fleet_cache_ttl=2.0):
        self.redis_url = (redis_url or "").strip()
        self.heartbeat_ttl = max(30, int(heartbeat_ttl))
        self.pgsync_ttl = max(30, int(pgsync_ttl))
        self.fleet_cache_ttl = max(0.5, float(fleet_cache_ttl))
        self._client = None
        self._local_lock = threading.Lock()
        self._local_snapshot_ts = 0.0
        self._local_snapshot = None

        if self.redis_url and _redis_pkg is not None:
            try:
                client = _redis_pkg.Redis.from_url(
                    self.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                )
                client.ping()
                self._client = client
            except Exception:
                self._client = None

    def is_connected(self):
        if self._client is None:
            return False
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def status_label(self):
        if not self.redis_url:
            return "disabled"
        if self.is_connected():
            return "ok"
        return "degraded"

    @staticmethod
    def _hb_key(hwid):
        return f"sl:hb:{hwid}"

    @staticmethod
    def _sync_key(hwid):
        return f"sl:pgsync:{hwid}"

    _FLEET_KEY = "sl:fleet:snapshot"

    @staticmethod
    def _decode_hb(raw):
        if not raw:
            return None
        return {
            "last_seen": str(raw.get("last_seen", "")),
            "last_seen_ts": _parse_float(raw.get("last_seen_ts"), 0.0),
            "ram_percent": _parse_int_or_none(raw.get("ram_percent")),
            "disk_percent": _parse_int_or_none(raw.get("disk_percent")),
            "uptime": str(raw.get("uptime", "")),
            "ip": str(raw.get("ip", "")),
        }

    def record_heartbeat(self, hwid, payload_dict):
        if self._client is None or not hwid:
            return False
        mapping = {
            "last_seen": str(payload_dict.get("last_seen") or ""),
            "last_seen_ts": str(float(payload_dict.get("last_seen_ts") or 0.0)),
            "ram_percent": "" if payload_dict.get("ram_percent") is None else str(int(payload_dict["ram_percent"])),
            "disk_percent": "" if payload_dict.get("disk_percent") is None else str(int(payload_dict["disk_percent"])),
            "uptime": str(payload_dict.get("uptime") or ""),
            "ip": str(payload_dict.get("ip") or ""),
        }
        key = self._hb_key(hwid)
        try:
            pipe = self._client.pipeline(transaction=False)
            pipe.hset(key, mapping=mapping)
            pipe.expire(key, self.heartbeat_ttl)
            pipe.execute()
            return True
        except Exception:
            return False

    def get_heartbeat(self, hwid):
        if self._client is None or not hwid:
            return None
        try:
            raw = self._client.hgetall(self._hb_key(hwid))
            return self._decode_hb(raw)
        except Exception:
            return None

    def get_heartbeats_bulk(self, hwids):
        if self._client is None or not hwids:
            return {}
        hwid_list = [h for h in hwids if h]
        if not hwid_list:
            return {}
        try:
            pipe = self._client.pipeline(transaction=False)
            for h in hwid_list:
                pipe.hgetall(self._hb_key(h))
            results = pipe.execute()
            out = {}
            for h, raw in zip(hwid_list, results):
                decoded = self._decode_hb(raw)
                if decoded is not None:
                    out[h] = decoded
            return out
        except Exception:
            return {}

    def delete_heartbeat(self, hwid):
        if self._client is None or not hwid:
            return False
        try:
            self._client.delete(self._hb_key(hwid), self._sync_key(hwid))
            return True
        except Exception:
            return False

    def should_flush_to_db(self, hwid):
        if self._client is None or not hwid:
            return True
        try:
            return int(self._client.exists(self._sync_key(hwid))) == 0
        except Exception:
            return True

    def mark_db_flushed(self, hwid):
        if self._client is None or not hwid:
            return False
        try:
            self._client.set(self._sync_key(hwid), "1", ex=self.pgsync_ttl)
            return True
        except Exception:
            return False

    def get_fleet_snapshot(self):
        if self._client is not None:
            try:
                raw = self._client.get(self._FLEET_KEY)
                if raw:
                    return json.loads(raw)
                return None
            except Exception:
                pass
        now_ts = time.time()
        with self._local_lock:
            if self._local_snapshot is not None and (now_ts - self._local_snapshot_ts) < self.fleet_cache_ttl:
                return dict(self._local_snapshot)
        return None

    def set_fleet_snapshot(self, snapshot_dict):
        if snapshot_dict is None:
            return
        with self._local_lock:
            self._local_snapshot_ts = time.time()
            self._local_snapshot = snapshot_dict
        if self._client is not None:
            try:
                ttl_ms = max(100, int(self.fleet_cache_ttl * 1000))
                self._client.set(self._FLEET_KEY, json.dumps(snapshot_dict), px=ttl_ms)
            except Exception:
                pass

    def invalidate_fleet_snapshot(self):
        with self._local_lock:
            self._local_snapshot_ts = 0.0
            self._local_snapshot = None
        if self._client is not None:
            try:
                self._client.delete(self._FLEET_KEY)
            except Exception:
                pass
