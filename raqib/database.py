import json
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device TEXT NOT NULL,
    ip TEXT NOT NULL,
    device_type TEXT NOT NULL,
    start_tick INTEGER NOT NULL,
    end_tick INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    peak REAL NOT NULL,
    alarms INTEGER NOT NULL,
    hits_if INTEGER NOT NULL,
    hits_ae INTEGER NOT NULL,
    hits_rf INTEGER NOT NULL,
    guess TEXT,
    truth TEXT,
    launched_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    label_col TEXT NOT NULL,
    normal_value TEXT NOT NULL,
    rows INTEGER NOT NULL,
    f1 REAL NOT NULL,
    folder TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


class Database:
    def __init__(self, path):
        self.path = path
        connection = self.connect()
        connection.executescript(SCHEMA)
        connection.close()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def run(self, sql, params=()):
        connection = self.connect()
        try:
            cursor = connection.execute(sql, params)
            connection.commit()
            return cursor.lastrowid
        finally:
            connection.close()

    def all(self, sql, params=()):
        connection = self.connect()
        try:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]
        finally:
            connection.close()

    def one(self, sql, params=()):
        rows = self.all(sql, params)
        return rows[0] if rows else None

    # users
    def count_users(self):
        return self.one("SELECT COUNT(*) AS n FROM users")["n"]

    def create_user(self, name, username, password_hash):
        role = "admin" if self.count_users() == 0 else "analyst"
        return self.run("INSERT INTO users (name, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                        (name, username, password_hash, role, now()))

    def user_by_id(self, user_id):
        return self.one("SELECT * FROM users WHERE id = ?", (user_id,))

    def user_by_username(self, username):
        return self.one("SELECT * FROM users WHERE username = ?", (username,))

    def list_users(self):
        return self.all("SELECT u.id, u.name, u.username, u.role, u.created_at, "
                        "(SELECT COUNT(*) FROM reports r WHERE r.user_id = u.id) AS reports "
                        "FROM users u ORDER BY u.id")

    def set_role(self, user_id, role):
        self.run("UPDATE users SET role = ? WHERE id = ?", (role, user_id))

    def delete_user(self, user_id):
        self.run("DELETE FROM users WHERE id = ?", (user_id,))

    # incidents
    def save_incident(self, record):
        record = dict(record, created_at=now())
        columns = ", ".join(record)
        marks = ", ".join("?" for _ in record)
        return self.run(f"INSERT INTO incidents ({columns}) VALUES ({marks})", tuple(record.values()))

    def list_incidents(self, truth="all", limit=200):
        where = {"all": "", "real": "WHERE i.truth IS NOT NULL", "false": "WHERE i.truth IS NULL"}[truth]
        return self.all("SELECT i.*, u.name AS launched_by_name FROM incidents i "
                        f"LEFT JOIN users u ON u.id = i.launched_by {where} ORDER BY i.id DESC LIMIT ?", (limit,))

    def incident_stats(self):
        row = self.one("SELECT COUNT(*) AS total, SUM(truth IS NOT NULL) AS real, SUM(truth IS NULL) AS false, "
                       "AVG(duration) AS duration FROM incidents")
        by_type = self.all("SELECT truth AS type, COUNT(*) AS n FROM incidents WHERE truth IS NOT NULL "
                           "GROUP BY truth ORDER BY n DESC")
        return dict(row, by_type=by_type)

    def clear_incidents(self):
        self.run("DELETE FROM incidents")

    # reports
    def save_report(self, user_id, filename, info, report, report_json):
        vote = next(row for row in report["table"] if row["key"] == "vote")
        return self.run("INSERT INTO reports (user_id, filename, label_col, normal_value, rows, f1, folder, data, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (user_id, filename, info["label_col"], info["normal"], report["rows"], float(vote["f1"]),
                         report["folder"], report_json, now()))

    def list_reports(self, user_id=None):
        sql = ("SELECT r.id, r.filename, r.label_col, r.rows, r.f1, r.created_at, r.user_id, u.name AS owner "
               "FROM reports r LEFT JOIN users u ON u.id = r.user_id")
        if user_id is None:
            return self.all(sql + " ORDER BY r.id DESC")
        return self.all(sql + " WHERE r.user_id = ? ORDER BY r.id DESC", (user_id,))

    def get_report(self, report_id):
        row = self.one("SELECT r.*, u.name AS owner FROM reports r LEFT JOIN users u ON u.id = r.user_id WHERE r.id = ?",
                       (report_id,))
        if row:
            row["report"] = json.loads(row.pop("data"))
        return row

    def delete_report(self, report_id):
        self.run("DELETE FROM reports WHERE id = ?", (report_id,))

    # settings
    def get_settings(self, defaults):
        saved = {row["key"]: row["value"] for row in self.all("SELECT key, value FROM settings")}
        return {key: saved.get(key, value) for key, value in defaults.items()}

    def save_settings(self, values):
        for key, value in values.items():
            self.run("INSERT INTO settings (key, value) VALUES (?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
