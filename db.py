# db.py
import sqlite3

DB_NAME = "totally_not_my_privateKeys.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # ── wipe any old schema ──
    cur.execute("DROP TABLE IF EXISTS keys")
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS auth_logs")

    # ── fresh KEYS ──
    cur.execute("""
        CREATE TABLE keys (
            kid           INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_key BLOB    NOT NULL,
            iv            BLOB    NOT NULL,
            exp           INTEGER NOT NULL
        )
    """)

    # users  
    cur.execute("""
        CREATE TABLE users(
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            email           TEXT    UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login      TIMESTAMP
        )
    """)

    # auth_logs  
    cur.execute("""
        CREATE TABLE auth_logs(
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip       TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id          INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
