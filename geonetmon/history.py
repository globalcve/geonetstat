"""Optional SQLite history: connection appear/vanish events + periodic samples.

The database lives at ``<cache>/history.db``. Writes are best-effort and never
raise into the UI. Sampling powers the in-window sparkline and lets you query
"what was talking to the network an hour ago" after the fact.
"""

import os
import sqlite3
import time

from . import config as cfg

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts        REAL    NOT NULL,
    event     TEXT    NOT NULL,   -- 'appear' | 'vanish'
    key       TEXT    NOT NULL,
    proto     TEXT,
    app       TEXT,
    pid       INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    country   TEXT,
    org       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS samples (
    ts        REAL    NOT NULL,
    total     INTEGER,
    established INTEGER,
    foreign_n INTEGER,
    up_bps    REAL,
    down_bps  REAL
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
"""


class History:
    def __init__(self, config):
        self.config = config
        self.path = os.path.join(cfg.cache_dir(), "history.db")
        self.conn = None
        self._open()

    def enabled(self):
        return bool(self.config.get("log_history", True))

    def _open(self):
        try:
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.executescript(_SCHEMA)
            self.conn.commit()
        except sqlite3.Error:
            self.conn = None

    # ---- writes ---------------------------------------------------------
    def log_event(self, event, obj):
        if not (self.conn and self.enabled()):
            return
        try:
            self.conn.execute(
                "INSERT INTO events (ts,event,key,proto,app,pid,remote_ip,"
                "remote_port,country,org) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (time.time(), event, obj.key, obj.proto, obj.application,
                 obj.pid, obj.remote_ip, obj.remote_port, obj.country, obj.org),
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def log_sample(self, total, established, foreign_n, up_bps, down_bps):
        if not (self.conn and self.enabled()):
            return
        try:
            self.conn.execute(
                "INSERT INTO samples (ts,total,established,foreign_n,up_bps,"
                "down_bps) VALUES (?,?,?,?,?,?)",
                (time.time(), total, established, foreign_n, up_bps, down_bps),
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    # ---- reads ----------------------------------------------------------
    def recent_samples(self, limit=120):
        if not self.conn:
            return []
        try:
            cur = self.conn.execute(
                "SELECT ts,total,established,foreign_n,up_bps,down_bps "
                "FROM samples ORDER BY ts DESC LIMIT ?", (limit,))
            return list(reversed(cur.fetchall()))
        except sqlite3.Error:
            return []

    def top_apps(self, since_seconds=86400, limit=10):
        if not self.conn:
            return []
        try:
            cur = self.conn.execute(
                "SELECT app, COUNT(*) c FROM events WHERE event='appear' "
                "AND ts > ? GROUP BY app ORDER BY c DESC LIMIT ?",
                (time.time() - since_seconds, limit))
            return cur.fetchall()
        except sqlite3.Error:
            return []

    def top_hosts(self, since_seconds=86400, limit=10):
        if not self.conn:
            return []
        try:
            cur = self.conn.execute(
                "SELECT remote_ip, COUNT(*) c FROM events WHERE event='appear' "
                "AND ts > ? AND remote_ip != '' GROUP BY remote_ip "
                "ORDER BY c DESC LIMIT ?",
                (time.time() - since_seconds, limit))
            return cur.fetchall()
        except sqlite3.Error:
            return []

    def top_countries(self, since_seconds=86400, limit=10):
        if not self.conn:
            return []
        try:
            cur = self.conn.execute(
                "SELECT country, COUNT(*) c FROM events WHERE event='appear' "
                "AND ts > ? AND country != '' GROUP BY country "
                "ORDER BY c DESC LIMIT ?",
                (time.time() - since_seconds, limit))
            return cur.fetchall()
        except sqlite3.Error:
            return []

    def event_count(self, since_seconds=86400):
        if not self.conn:
            return 0
        try:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE event='appear' AND ts > ?",
                (time.time() - since_seconds,))
            return cur.fetchone()[0]
        except sqlite3.Error:
            return 0

    def prune(self, keep_days=30):
        if not self.conn:
            return
        try:
            cutoff = time.time() - keep_days * 86400
            self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            self.conn.commit()
        except sqlite3.Error:
            pass

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
            self.conn = None
