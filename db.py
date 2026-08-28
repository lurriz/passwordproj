import secrets
import sqlite3
from cryptography.fernet import Fernet
from pathlib import Path

BUSY_TIMEOUT_SECONDS = 5.0

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "vault.db"
LEGACY_KEY_PATH = BASE_DIR.parent / "key.txt"

def legacy_key():
    """The single shared key every entry used before per-user keys.

    Only needed to migrate a user's entries the first time they log in.
    Returns None once key.txt is gone, which is the point at which no
    unmigrated entry can exist any more.
    """
    if not LEGACY_KEY_PATH.exists():
        return None

    with open(LEGACY_KEY_PATH, "rb") as key_file:
        return key_file.read().strip()

def connect():
    """Open a connection with foreign keys enforced.

    SQLite disables them per connection by default, and without this the
    ON DELETE CASCADE on vault.user_id never fires.
    """
    conn = sqlite3.connect(DB_PATH, timeout=BUSY_TIMEOUT_SECONDS)
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets readers run while a writer holds the lock, which is what stops
    # "database is locked" once more than one request is in flight.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_SECONDS * 1000)}")

    return conn

def init_db():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            kdf_salt BLOB,
            wrapped_key BLOB,
            email TEXT,
            recovery_salt BLOB,
            recovery_wrapped_key BLOB,
            token_version INTEGER NOT NULL DEFAULT 0,
            email_verified INTEGER NOT NULL DEFAULT 0,
            pending_email TEXT,
            email_token_hash TEXT,
            email_token_expires REAL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # Existing databases predate the key columns. They stay nullable: a user
    # with no wrapped_key has not migrated yet and gets one at next login.
    existing = [row[1] for row in cursor.execute("PRAGMA table_info(users)")]

    for column, kind in (
        ("kdf_salt", "BLOB"),
        ("wrapped_key", "BLOB"),
        ("email", "TEXT"),
        ("recovery_salt", "BLOB"),
        ("recovery_wrapped_key", "BLOB"),
        ("token_version", "INTEGER NOT NULL DEFAULT 0"),
        ("email_verified", "INTEGER NOT NULL DEFAULT 0"),
        ("pending_email", "TEXT"),
        ("email_token_hash", "TEXT"),
        ("email_token_expires", "REAL"),
    ):
        if column not in existing:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column} {kind}")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            scope TEXT NOT NULL,
            key TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0,
            PRIMARY KEY (scope, key)
        )
    """)

    # No foreign key to users: the record of what happened must outlive the
    # account it happened to.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL DEFAULT (datetime('now')),
            user_id INTEGER,
            username TEXT,
            event TEXT NOT NULL,
            detail TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at)")

    conn.commit()
    conn.close()

# ---------- Rate limiting ----------
# In the database rather than module state so the counters are shared by every
# thread and process, and survive a restart. These are not secrets, unlike the
# vault keys, which is why they can live on disk.

def rate_limit_remaining(scope, key, now):
    conn = connect()

    row = conn.execute("""
        SELECT locked_until
        FROM rate_limits
        WHERE scope = ? AND key = ?
    """, (scope, key)).fetchone()

    conn.close()

    if row is None:
        return 0

    remaining = row[0] - now

    return int(remaining) + 1 if remaining > 0 else 0


def rate_limit_fail(scope, key, max_attempts, lockout_seconds, now):
    """Count a failure. Returns attempts left, or 0 once locked out."""
    conn = connect()

    try:
        # IMMEDIATE takes the write lock up front, so two requests cannot both
        # read the same count and each write back the same increment.
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT attempts FROM rate_limits WHERE scope = ? AND key = ?
        """, (scope, key)).fetchone()

        attempts = (row[0] if row else 0) + 1

        if attempts < max_attempts:
            conn.execute("""
                INSERT INTO rate_limits (scope, key, attempts, locked_until)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(scope, key) DO UPDATE SET attempts = excluded.attempts
            """, (scope, key, attempts))
            conn.commit()

            return max_attempts - attempts

        conn.execute("""
            INSERT INTO rate_limits (scope, key, attempts, locked_until)
            VALUES (?, ?, 0, ?)
            ON CONFLICT(scope, key) DO UPDATE
            SET attempts = 0, locked_until = excluded.locked_until
        """, (scope, key, now + lockout_seconds))
        conn.commit()

        return 0
    finally:
        conn.close()


def rate_limit_reset(scope, key):
    conn = connect()

    with conn:
        conn.execute("DELETE FROM rate_limits WHERE scope = ? AND key = ?", (scope, key))

    conn.close()


def rate_limit_sweep(now):
    """Drop expired rows so the table cannot grow without bound."""
    conn = connect()

    with conn:
        conn.execute(
            "DELETE FROM rate_limits WHERE locked_until < ? AND attempts = 0",
            (now,),
        )

    conn.close()

# ---------- Audit log ----------

def record_event(event, user_id=None, username=None, detail=None):
    conn = connect()

    with conn:
        conn.execute("""
            INSERT INTO audit_log (user_id, username, event, detail)
            VALUES (?, ?, ?, ?)
        """, (user_id, username, event, detail))

    conn.close()


def events_for_user(user_id, limit=50):
    """One account's own history, newest first.

    Scoped to the caller: the table also holds rows for other accounts and for
    failed logins against usernames that do not exist.
    """
    conn = connect()

    rows = conn.execute("""
        SELECT at, event, detail
        FROM audit_log
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
    """, (user_id, limit)).fetchall()

    conn.close()

    return [{"at": at, "event": event, "detail": detail} for at, event, detail in rows]


def recent_events(limit=50):
    conn = connect()

    rows = conn.execute("""
        SELECT at, user_id, username, event, detail
        FROM audit_log
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()

    return [
        {"at": at, "user_id": uid, "username": name, "event": event, "detail": detail}
        for at, uid, name, event, detail in rows
    ]

# ---------- Users ----------

def create_user(username, password_hash, pin_hash, kdf_salt=None, wrapped_key=None,
                email=None, recovery_salt=None, recovery_wrapped_key=None):
    """Insert a user. Raises sqlite3.IntegrityError if the username is taken."""
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (username, password_hash, pin_hash, kdf_salt, wrapped_key,
                           email, recovery_salt, recovery_wrapped_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, password_hash, pin_hash, kdf_salt, wrapped_key,
          email, recovery_salt, recovery_wrapped_key))

    user_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return user_id

def get_user_by_username(username):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, password_hash, pin_hash, kdf_salt, wrapped_key,
               email, recovery_salt, recovery_wrapped_key, token_version,
               email_verified, pending_email
        FROM users
        WHERE username = ?
    """, (username,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    (id, username, password_hash, pin_hash, kdf_salt, wrapped_key,
     email, recovery_salt, recovery_wrapped_key, token_version,
     email_verified, pending_email) = row

    return {
        "id": id,
        "username": username,
        "password_hash": password_hash,
        "pin_hash": pin_hash,
        "kdf_salt": kdf_salt,
        "wrapped_key": wrapped_key,
        "email": email,
        "recovery_salt": recovery_salt,
        "recovery_wrapped_key": recovery_wrapped_key,
        "token_version": token_version,
        "email_verified": bool(email_verified),
        "pending_email": pending_email
    }

def get_user_by_id(user_id):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, password_hash, pin_hash, kdf_salt, wrapped_key,
               email, recovery_salt, recovery_wrapped_key, token_version,
               email_verified, pending_email
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    (id, username, password_hash, pin_hash, kdf_salt, wrapped_key,
     email, recovery_salt, recovery_wrapped_key, token_version,
     email_verified, pending_email) = row

    return {
        "id": id,
        "username": username,
        "password_hash": password_hash,
        "pin_hash": pin_hash,
        "kdf_salt": kdf_salt,
        "wrapped_key": wrapped_key,
        "email": email,
        "recovery_salt": recovery_salt,
        "recovery_wrapped_key": recovery_wrapped_key,
        "token_version": token_version,
        "email_verified": bool(email_verified),
        "pending_email": pending_email
    }

def set_user_key(user_id, kdf_salt, wrapped_key):
    """Store the salt and the vault key wrapped under the password-derived key."""
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET kdf_salt = ?, wrapped_key = ?
        WHERE id = ?
    """, (kdf_salt, wrapped_key, user_id))

    conn.commit()
    conn.close()

def set_password(user_id, password_hash, kdf_salt, wrapped_key):
    """Change the password and re-wrap the vault key in one write.

    The vault key itself does not change, so no entry is re-encrypted.

    token_version is bumped in the same statement: sessions carry the value
    they saw at login, so every other session stops validating immediately.
    Returns the new token_version for the caller to put in its own session.
    """
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash = ?, kdf_salt = ?, wrapped_key = ?,
            token_version = token_version + 1
        WHERE id = ?
    """, (password_hash, kdf_salt, wrapped_key, user_id))

    cursor.execute("SELECT token_version FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()

    conn.commit()
    conn.close()

    return row[0] if row else None

def set_pin(user_id, pin_hash):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET pin_hash = ?
        WHERE id = ?
    """, (pin_hash, user_id))

    conn.commit()
    conn.close()

def get_pin_hash(user_id):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT pin_hash
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return row[0]

# ---------- Vault entries ----------
#
# Every query below filters on user_id in the WHERE clause rather than
# fetching a row and comparing owners afterwards. An entry belonging to
# somebody else is then indistinguishable from one that does not exist,
# so the API cannot be used to probe which ids are real.

def encrypt_password(password, key):
    return Fernet(key).encrypt(password.encode())

def decrypt_password(encrypted, key):
    return Fernet(key).decrypt(encrypted).decode()

def store_entry(user_id, site, username, password, key):
    encrypted = encrypt_password(password, key)

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO vault (user_id, site, username, password)
        VALUES (?, ?, ?, ?)
  """,(user_id, site, username, encrypted))

    conn.commit()
    conn.close()

def get_entries(user_id, site="", username=""):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, site, username
        FROM vault
        WHERE user_id = ?
        AND site LIKE ?
        AND username LIKE ?
        ORDER BY id
    """, (user_id, f"%{site}%", f"%{username}%"))

    rows = cursor.fetchall()

    conn.close()

    entries = []

    # "number" is the row's position in this user's list, so it always runs
    # 1..N with no gaps. The id stays the handle every other route uses.
    for number, (id, site, username) in enumerate(rows, start=1):
        entries.append({
            "id": id,
            "number": number,
            "site": site,
            "username": username
        })
    
    return entries

def get_entry_meta_by_id(entry_id, user_id):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, site, username
        FROM vault
        WHERE id = ?
        AND user_id = ?
    """, (entry_id, user_id))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    id, site, username = row

    return {
        "id": id,
        "site": site,
        "username": username
    }

def get_entry_by_id(entry_id, user_id, key):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, site, username, password
        FROM vault
        WHERE id = ?
        AND user_id = ?
    """, (entry_id, user_id))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    id, site, username, encrypted = row

    return {
        "id": id,
        "site": site,
        "username": username,
        "password": decrypt_password(encrypted, key)
    }
    
def update_entry(entry_id, user_id, site, username, password, key):
    """Returns the number of rows changed - 0 if the entry is not the user's."""
    encrypted = encrypt_password(password, key)

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE vault
        SET site = ?, username = ?, password = ?
        WHERE id = ?
        AND user_id = ?
    """, (site, username, encrypted, entry_id, user_id))

    changed = cursor.rowcount

    conn.commit()
    conn.close()

    return changed

def delete_entry(entry_id, user_id):
    """Returns the number of rows deleted - 0 if the entry is not the user's."""
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM vault
        WHERE id = ?
        AND user_id = ?
    """,(entry_id, user_id))

    changed = cursor.rowcount

    conn.commit()
    conn.close()

    return changed

def adopt_user_key(user_id, old_key, new_key, kdf_salt, wrapped_key):
    """Move a user onto their own vault key, entries and key record together.

    Used once per user, the first time they log in after per-user keys were
    introduced. Both writes share one transaction, so the entries and the
    stored key can never disagree: either the user is fully migrated or they
    are still legacy and can simply try again.

    old_key may be None when the user has no entries to move.
    """
    conn = connect()

    try:
        # IMMEDIATE so the read and the writes are one atomic step. Two
        # simultaneous first logins would otherwise both re-encrypt from the
        # shared key and each store its own wrapped key, leaving the entries
        # under one key and the stored key another - an unreadable vault.
        conn.execute("BEGIN IMMEDIATE")

        already = conn.execute(
            "SELECT wrapped_key FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if already is None or already[0] is not None:
            # Another request migrated this user while we waited for the lock.
            conn.rollback()
            return 0

        rows = conn.execute("""
            SELECT id, password
            FROM vault
            WHERE user_id = ?
        """, (user_id,)).fetchall()

        if rows and old_key is None:
            conn.rollback()
            raise RuntimeError(
                f"user {user_id} has {len(rows)} entries but key.txt is gone - cannot migrate them"
            )

        reencrypted = [
            (Fernet(new_key).encrypt(Fernet(old_key).decrypt(blob)), entry_id)
            for entry_id, blob in rows
        ]

        conn.executemany("UPDATE vault SET password = ? WHERE id = ?", reencrypted)
        conn.execute(
            "UPDATE users SET kdf_salt = ?, wrapped_key = ? WHERE id = ?",
            (kdf_salt, wrapped_key, user_id),
        )

        conn.commit()

        return len(reencrypted)
    finally:
        conn.close()

def set_recovery(user_id, recovery_salt, recovery_wrapped_key):
    """Store a second wrapping of the vault key, under a recovery code.

    The code itself is never stored - only what it unwraps. That is what keeps
    the server unable to open a vault on its own.
    """
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET recovery_salt = ?, recovery_wrapped_key = ?
        WHERE id = ?
    """, (recovery_salt, recovery_wrapped_key, user_id))

    conn.commit()
    conn.close()

def start_email_change(user_id, email, token_hash, expires):
    """Park a new address as pending until its owner proves they can read it.

    The live address is untouched, so a mistyped or hostile change cannot
    redirect recovery codes before it has been confirmed.
    """
    conn = connect()

    with conn:
        conn.execute("""
            UPDATE users
            SET pending_email = ?, email_token_hash = ?, email_token_expires = ?
            WHERE id = ?
        """, (email, token_hash, expires, user_id))

    conn.close()


def confirm_email(user_id, token_hash, now):
    """Promote the pending address if the token matches and has not expired.

    Returns the confirmed address, or None.
    """
    conn = connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT pending_email, email_token_hash, email_token_expires
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        if row is None:
            conn.rollback()
            return None

        pending, stored_hash, expires = row

        if not pending or not stored_hash or not expires or expires < now:
            conn.rollback()
            return None

        if not secrets.compare_digest(stored_hash, token_hash):
            conn.rollback()
            return None

        conn.execute("""
            UPDATE users
            SET email = ?, email_verified = 1, pending_email = NULL,
                email_token_hash = NULL, email_token_expires = NULL
            WHERE id = ?
        """, (pending, user_id))

        conn.commit()

        return pending
    finally:
        conn.close()
