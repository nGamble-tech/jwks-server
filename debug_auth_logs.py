import sqlite3

DB_NAME = "totally_not_my_privateKeys.db"

def show_auth_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM auth_logs")
    logs = cursor.fetchall()

    print("\n AUTH LOG ENTRIES:")
    for log in logs:
        print(log)

    conn.close()

if __name__ == "__main__":
    show_auth_logs()
