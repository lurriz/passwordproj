# PassMaker

A self-hosted password manager: generate passwords, store them encrypted, and
get them back out behind a second factor. Flask, SQLite, vanilla JavaScript, no
build step.

## How it protects things

Each account has a random **vault key** that encrypts its entries. That key is
never stored in the clear — it is wrapped with a key derived from the account
password (scrypt), and only the wrapped form goes in the database. Signing in
unwraps it into **process memory only**; it is never written to disk or a cache,
because putting it there would place the key beside the ciphertext it protects.

Consequences worth knowing before you rely on this:

- Restarting the server drops every in-memory key, so everyone signs in again.
- Changing a password re-wraps the same vault key, so no entry is re-encrypted.
- A forgotten password **plus** a lost recovery code means that vault is gone.
  There is no escrow and no admin override. That is deliberate.

Revealing, copying, editing or deleting an entry needs a separate **PIN**, which
is bcrypt-hashed and rate-limited independently of the password.

## Running it locally

Secrets and data live in the parent directory, outside the repository:

```
personal projects/
├── .env          # credentials and configuration
├── vault.db      # the database
└── passwordproj/ # this repository
```

Install and start:

```bash
pip install -r requirements.txt
python app.py
```

`.env` needs at minimum:

```
SECRET_KEY=<64 random hex characters>
```

Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`.
Without it the app refuses to start.

## Creating an account

```bash
python create_user.py
```

Prompts for a username, recovery email, password and PIN. Nothing is echoed and
only hashes reach the database. It prints a recovery code once — save it. If
SMTP is configured it is emailed instead.

## Deploying

See [DEPLOYMENT.md](DEPLOYMENT.md). The short version: **one process, many
threads**, `PRODUCTION=1`, TLS in front, and never copy `key.txt` or any
`vault.db.*.bak` to the server.

## Layout

| File | Role |
|---|---|
| `app.py` | Routes, sessions, CSRF, rate limiting, security headers |
| `db.py` | SQLite access; every vault query is scoped by owner |
| `crypto.py` | Key derivation, wrapping, recovery codes, password hashing |
| `mailer.py` | Recovery and confirmation email |
| `serve.py` | Production entrypoint (waitress) |
| `create_user.py` | Account creation CLI |
| `migrate_users.py` | One-shot migration to per-user keys |
| `templates/` | Jinja pages; `_sidebar.html` is shared by all of them |
| `static/` | `base.css` holds the design tokens; one stylesheet per page |

## Pages

- **Home** — links to the rest
- **Generator** — make a password and save it
- **Vault** — search, reveal, edit, delete
- **Activity** — your own recent account events
- **Settings** — password, PIN, recovery address

## Known limits

- SQLite with WAL: fine for one process and modest traffic, not for heavy
  concurrent writes.
- Passwords are checked for length only, not against breach lists.
- The audit log is never pruned and nothing alerts on it — it is a record to
  read, not a monitor.
- The recovery code is delivered by email, so whoever can read that mailbox can
  take the account over.
