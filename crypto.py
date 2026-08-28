"""Password-derived key wrapping for per-user vaults.

Each user gets a random vault key that encrypts their entries. That key is
never stored in the clear: it is wrapped with a second key derived from the
user's password, and only the wrapped form is written to the database.

The indirection is what makes a password change cheap. Changing a password
re-wraps one small blob; the vault key underneath is unchanged, so not a
single entry has to be re-encrypted.
"""

import base64
import secrets

import bcrypt

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_BYTES = 16

# scrypt cost. n must be a power of two. Measured on this machine: 2**16
# with r=8 costs ~0.16s and 64MB per derivation, which is the point - that
# is what every guess costs an attacker too. Raise the exponent to raise it.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1


def derive_wrapping_key(password, salt):
    """Turn a password into the key that wraps a vault key."""
    raw = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(password.encode())

    return base64.urlsafe_b64encode(raw)


def new_key_material(password):
    """A fresh vault key, plus the salt and wrapped form to store alongside it."""
    salt = secrets.token_bytes(SALT_BYTES)
    vault_key = Fernet.generate_key()
    wrapped = Fernet(derive_wrapping_key(password, salt)).encrypt(vault_key)

    return vault_key, salt, wrapped


def unwrap_vault_key(password, salt, wrapped):
    """Recover a vault key. Raises cryptography.fernet.InvalidToken on a wrong password."""
    return Fernet(derive_wrapping_key(password, salt)).decrypt(wrapped)


def rewrap_vault_key(vault_key, new_password):
    """Wrap an existing vault key under a new password. Returns (salt, wrapped)."""
    salt = secrets.token_bytes(SALT_BYTES)
    wrapped = Fernet(derive_wrapping_key(new_password, salt)).encrypt(vault_key)

    return salt, wrapped


# A recovery code is simply a second secret that wraps the same vault key, so
# it goes through derive_wrapping_key exactly like a password does. 15 random
# bytes is 120 bits - far beyond guessing, and base32 avoids the character
# pairs people misread when copying by hand.
RECOVERY_BYTES = 15
RECOVERY_GROUP = 4


def new_recovery_code():
    """A fresh recovery code, formatted for a human to copy."""
    raw = base64.b32encode(secrets.token_bytes(RECOVERY_BYTES)).decode().rstrip("=")

    return "-".join(raw[i:i + RECOVERY_GROUP] for i in range(0, len(raw), RECOVERY_GROUP))


def normalize_recovery_code(code):
    """Canonical form, so dashes, spaces and case do not matter on entry."""
    return "".join(code.split()).replace("-", "").upper()


# bcrypt hashes at most 72 bytes and raises on anything longer, which turned
# an over-long password into a 500 on every route that touched one.
BCRYPT_MAX_BYTES = 72


def secret_too_long(secret):
    return len(secret.encode()) > BCRYPT_MAX_BYTES


def hash_secret(secret):
    """bcrypt a password or PIN. Callers must reject over-long input first."""
    if secret_too_long(secret):
        raise ValueError(f"secret exceeds bcrypt's {BCRYPT_MAX_BYTES}-byte limit")

    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def verify_secret(secret, hashed):
    """Check a password or PIN.

    Over-long input returns False rather than raising: no stored hash can have
    come from it, so it simply cannot be the right secret.
    """
    if secret_too_long(secret):
        return False

    return bcrypt.checkpw(secret.encode(), hashed.encode() if isinstance(hashed, str) else hashed)
