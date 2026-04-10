import sqlite3
from datetime import datetime

DB_PATH = "pubwisec.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # password history (ikut schema awak: status ACTIVE/INACTIVE)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password TEXT NOT NULL,
            changed_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE'
        )
    """)

    # alerts
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ✅ FIX UTAMA: pastikan hanya 1 ACTIVE
def add_password(password: str):
    conn = get_conn()
    cur = conn.cursor()

    # semua ACTIVE -> INACTIVE dulu
    cur.execute("""
        UPDATE password_history
        SET status = 'INACTIVE'
        WHERE status = 'ACTIVE'
    """)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # insert baru jadi ACTIVE
    cur.execute("""
        INSERT INTO password_history (password, changed_at, status)
        VALUES (?, ?, 'ACTIVE')
    """, (password, now))

    conn.commit()
    conn.close()


def get_latest_password():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM password_history
        WHERE status = 'ACTIVE'
        ORDER BY id DESC
        LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()
    return row


def get_password_history(limit: int = 200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM password_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def add_alert(alert_type: str, severity: str, message: str):
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT INTO alerts (alert_type, severity, message, created_at)
        VALUES (?, ?, ?, ?)
    """, (alert_type, severity, message, now))

    conn.commit()
    conn.close()


def get_alerts(limit: int = 50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def acknowledge_all_alerts():
    # Kalau table awak takde is_acknowledged, function ni just placeholder.
    # Biar tak crash bila route /acknowledge dipanggil.
    return