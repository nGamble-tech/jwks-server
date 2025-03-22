import sqlite3

DB_NAME = "totally_not_my_privateKeys.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Optional: makes rows accessible like dictionaries
    return conn

def initialize_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    conn.commit()
    conn.close()
