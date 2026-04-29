import sqlite3
from cryptography.fernet import Fernet

key = b"gVcaRPHaWFAcdh81bF-Ly1jTnROJ5XwQ-uNe1u0m3OQ="
fernet = Fernet(key)

def init_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   site TEXT NOT NULL,
                   username TEXT NOT NULL,
                   password BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def encrypt_password(password):
    return fernet.encrypt(password.encode())

def store_entry(site, username, password):
    encrypted = encrypt_password(password)

    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO vault (site, username, password)
        VALUES (?, ?, ?)
  """,(site, username, encrypted))
        
    conn.commit()
    conn.close()

def get_entries():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, site, username, password FROM vault")
    rows = cursor.fetchall()

    conn.close()

    entries = []
    for id, site, username, encrypted in rows:
            entries.append({
                "id": id,
                "site": site,
                "username": username,
                "password": encrypted.decode()  # convert bytes → string
            })

    return entries

init_db()