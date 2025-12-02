import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")

cur.execute("INSERT INTO users (username, password) VALUES ('admin', '7amoelgen')")
conn.commit()
conn.close()

print("User added.")
import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS product (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    description TEXT
)
""")

cur.execute("INSERT INTO product (name, price, description) VALUES ('Cyber Laptop', 999.99, 'Hacked Edition')")
cur.execute("INSERT INTO product (name, price, description) VALUES ('USB Rubber Ducky', 49.99, 'Payload Ready')")
cur.execute("INSERT INTO product (name, price, description) VALUES ('WiFi Pineapple', 199.99, 'MITM Toolkit')")
conn.commit()
conn.close()

print("Products added.")
