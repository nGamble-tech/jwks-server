import sqlite3

conn = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print(" Tables in DB:", tables)

cursor.execute("SELECT * FROM keys")
rows = cursor.fetchall()

print(" Keys in DB:")
for row in rows:
    print(row)

conn.close()
