"""One-shot migration: add the users table and give every vault entry an owner.

Safe to re-run - it checks whether vault.user_id already exists and stops if so.

The first user is seeded from the .env credentials. Both values there are
already bcrypt hashes, so no plaintext password or PIN is involved and the
existing login and PIN keep working unchanged.
"""

import os
import shutil
import sqlite3
import sys
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "vault.db"
BACKUP_PATH = BASE_DIR.parent / "vault.db.bak"

load_dotenv()
load_dotenv(BASE_DIR.parent / ".env")

USERNAME = os.getenv("LOGIN_USERNAME")
PASSWORD_HASH = os.getenv("LOGIN_PASSWORD_HASH")
PIN_HASH = os.getenv("REVEAL_PIN_HASH")


def vault_has_user_id(conn):
    return "user_id" in [row[1] for row in conn.execute("PRAGMA table_info(vault)")]


def main():
    if not DB_PATH.exists():
        sys.exit(f"No database at {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)

    # Must be set outside a transaction, and must be off while the table is
    # rebuilt or the DROP would cascade away rows we are about to keep.
    conn.execute("PRAGMA foreign_keys = OFF")

    try:
        if vault_has_user_id(conn):
            print("vault.user_id already exists - nothing to do.")
            return

        if not (USERNAME and PASSWORD_HASH and PIN_HASH):
            sys.exit("Missing LOGIN_USERNAME / LOGIN_PASSWORD_HASH / REVEAL_PIN_HASH in .env")

        shutil.copy2(DB_PATH, BACKUP_PATH)
        print(f"backed up   -> {BACKUP_PATH}")

        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    pin_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

            cursor = conn.execute("""
                INSERT INTO users (username, password_hash, pin_hash)
                VALUES (?, ?, ?)
            """, (USERNAME, PASSWORD_HASH, PIN_HASH))

            seed_id = cursor.lastrowid

            conn.execute("""
                CREATE TABLE vault_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    site TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password BLOB NOT NULL
                )
            """)

            moved = conn.execute("""
                INSERT INTO vault_new (id, user_id, site, username, password)
                SELECT id, ?, site, username, password
                FROM vault
            """, (seed_id,)).rowcount

            conn.execute("DROP TABLE vault")
            conn.execute("ALTER TABLE vault_new RENAME TO vault")

        print(f"seeded user -> {USERNAME!r} (id {seed_id})")
        print(f"moved       -> {moved} vault entries")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
