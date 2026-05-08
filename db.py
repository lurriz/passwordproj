import sqlite3
from cryptography.fernet import Fernet
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "vault.db"
KEY_PATH = BASE_DIR.parent / "key.txt"

with open(KEY_PATH, "rb") as key_file:
    key = key_file.read().strip()

fernet = Fernet(key)

def init_db():
    conn = sqlite3.connect(DB_PATH)
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

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO vault (site, username, password)
        VALUES (?, ?, ?)
  """,(site, username, encrypted))
        
    conn.commit()
    conn.close()

def get_entries(site="", username=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, site, username
        FROM vault
        WHERE site LIKE ?
        AND username LIKE ?
    """, (f"%{site}%", f"%{username}%"))

    rows = cursor.fetchall()

    conn.close()

    entries = []

    for id, site, username in rows:
        entries.append({
            "id": id,
            "site": site,
            "username": username
        })
    
    return entries

def decrypt_password(encrypted):
    return fernet.decrypt(encrypted).decode()

def get_entry_by_id(entry_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, site, username, password
        FROM vault
        WHERE id = ?
    """, (entry_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    id, site, username, encrypted = row

    return {
        "id": id,
        "site": site,
        "username": username,
        "password": decrypt_password(encrypted)
    }
    
def update_entry(entry_id, site, username, password):
    encrypted = encrypt_password(password)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE vault
        SET site = ?, username = ?, password = ?
        WHERE id = ?
    """, (site, username, encrypted, entry_id))

    conn.commit()
    conn.close()

def delete_entry(entry_id):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM vault
        WHERE id = ?
    """,(entry_id,))

    conn.commit()
    conn.close()