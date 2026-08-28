"""Create a vault user.

Run it directly:  python create_user.py

Prompts for the password and PIN with getpass, so neither is echoed to the
screen or left in shell history. Only bcrypt hashes reach the database.
"""

import getpass
import sqlite3
import sys

from crypto import (
    new_key_material,
    new_recovery_code,
    normalize_recovery_code,
    rewrap_vault_key,
    hash_secret,
    secret_too_long,
    BCRYPT_MAX_BYTES,
)
from db import init_db, create_user
from mailer import send_email, recovery_email_body, RECOVERY_SUBJECT


def prompt_secret(label):
    """Ask twice and require a non-empty match."""
    while True:
        first = getpass.getpass(f"{label}: ")

        if not first.strip():
            print(f"  {label} cannot be empty.")
            continue

        if secret_too_long(first):
            print(f"  {label} must be at most {BCRYPT_MAX_BYTES} bytes.")
            continue

        if first != getpass.getpass(f"Confirm {label.lower()}: "):
            print("  Entries did not match, try again.")
            continue

        return first


def main():
    init_db()

    username = input("Username: ").strip()

    if not username:
        sys.exit("Username cannot be empty.")

    email = input("Email for recovery codes (blank to print the code here): ").strip()

    password = prompt_secret("Password")
    pin = prompt_secret("PIN")

    password_hash = hash_secret(password)
    pin_hash = hash_secret(pin)

    # Login derives the vault key again from the password, so only the salt
    # and the wrapped form are stored. The key is kept here just long enough
    # to wrap a second copy under the recovery code.
    vault_key, kdf_salt, wrapped_key = new_key_material(password)

    code = new_recovery_code()
    recovery_salt, recovery_wrapped = rewrap_vault_key(vault_key, normalize_recovery_code(code))

    try:
        user_id = create_user(
            username, password_hash, pin_hash, kdf_salt, wrapped_key,
            email or None, recovery_salt, recovery_wrapped,
        )
    except sqlite3.IntegrityError:
        sys.exit(f"A user named {username!r} already exists.")

    print(f"Created user {username!r} (id {user_id}).")

    sent, detail = send_email(email, RECOVERY_SUBJECT, recovery_email_body(username, code))

    if sent:
        print(f"Recovery code emailed to {email}.")
        return

    if email:
        print()
        print(f"Could not email the code ({detail}).")

    print()
    print("Recovery code - save it now, it is not stored anywhere:")
    print()
    print(f"    {code}")
    print()
    print("Without it, forgetting the password means losing this vault.")


if __name__ == "__main__":
    main()
