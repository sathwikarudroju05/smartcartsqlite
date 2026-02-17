import sqlite3

# This creates a SQLite file named smartcart_db.db
conn = sqlite3.connect("smartcart.db")

# Read your schema.sql which contains all your tables
with open("schema.sql", "r") as f:
    conn.executescript(f.read())

conn.commit()
conn.close()

print("smartcart_db database initialized successfully.")
