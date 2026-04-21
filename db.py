import sqlite3

def init_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   site TEXT NOT NULL,
                   username TEXT NOT NULL,
                   password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def store_entry(site, username, password):
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO vault (site, username, password)
        VALUES (?, ?, ?)
  """,(site, username, password))
        
    conn.commit()
    conn.close

init_db()