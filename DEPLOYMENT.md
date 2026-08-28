# Deploying this

## The one constraint that shapes everything

**Run exactly one process.** Vault keys live only in that process's memory and
are deliberately never written to disk or to a cache. Storing them in Redis or
a table would put each user's decryption key beside the ciphertext it protects,
which is precisely what per-user encryption exists to prevent.

Threads share that memory, so scale with threads, not workers:

```
PRODUCTION=1 THREADS=8 python serve.py
```

A second process would hand some requests to a worker that does not hold the
user's key, locking them out at random. If you ever outgrow one process, the
answer is a deliberate design for key custody - not more workers.

## Before the first deploy

- [ ] `PRODUCTION=1` in the environment. Without it `serve.py` refuses to start,
      because the session cookie would not be marked `Secure`.
- [ ] Terminate TLS in front of the app (nginx, Caddy, a platform router) and
      pass `X-Forwarded-Proto`. The app sets HSTS only when `PRODUCTION=1`.
- [ ] `SECRET_KEY` set to a long random value, different from any other install.
      Changing it logs everyone out.
- [ ] SMTP configured (`SMTP_HOST`, `SMTP_FROM`, credentials). Without it,
      recovery codes and address confirmations cannot be delivered, and the app
      falls back to displaying them in the browser - fine locally, wrong on the
      internet.
- [ ] **`key.txt` must not be copied to the server.** It decrypts every entry
      written before per-user keys existed. Delete it once every account has
      logged in at least once; the app logs a warning while it is present.
- [ ] **`vault.db.bak` and `vault.db.pre-keys.bak` must not be deployed or
      backed up anywhere reachable.** They contain entries encrypted under the
      old shared key, so they undo per-user encryption entirely.
- [ ] `.env`, `vault.db` and the backups live outside the web root and are not
      in git. Check `.gitignore` still covers them.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `PRODUCTION` | `0` | Set to `1`. Marks the cookie `Secure`, enables HSTS. |
| `SECRET_KEY` | required | Signs the session cookie. |
| `HOST` / `PORT` | `127.0.0.1` / `5001` | Bind behind the reverse proxy. |
| `THREADS` | `8` | Concurrency. Do **not** add processes. |
| `AUTO_LOCK_MINUTES` | `15` | Idle timeout; also drops the in-memory key. |
| `MIN_PASSWORD_LENGTH` | `12` | Applies when setting a password, not to existing ones. |
| `MIN_PIN_LENGTH` | `6` | Same. |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_LOCKOUT_SECONDS` | `5` / `300` | Shared across threads via the database. |
| `PIN_MAX_ATTEMPTS` / `PIN_LOCKOUT_SECONDS` | `5` / `300` | Same. |
| `MAX_CONTENT_LENGTH` | `65536` | Request body cap, in bytes. |
| `EMAIL_TOKEN_HOURS` | `24` | Lifetime of an address-confirmation link. |

`app.py` remains the development entrypoint and still refuses to enable the
Werkzeug debugger on a non-loopback interface.

## Known limits

- **SQLite.** WAL is on and a busy timeout is set, which is enough for a single
  process with modest traffic. Heavy concurrent writes want Postgres.
- **A forgotten password plus a lost recovery code means that vault is gone.**
  There is no escrow, by design.
- **The recovery code is emailed**, so whoever can read that mailbox can take
  the account. Confirmed addresses only, but that is the residual risk.
- **No breach-list check** on chosen passwords, only a length floor.
- **The audit log is never pruned** and nothing alerts on it; it is a record to
  read after the fact, not a monitor.
