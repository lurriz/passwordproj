from flask import Flask, render_template, request, jsonify, redirect, session, abort, url_for
from pass_generator import make_password
from db import (
    init_db,
    store_entry,
    get_entries,
    get_entry_by_id,
    get_entry_meta_by_id,
    update_entry,
    delete_entry,
    get_user_by_username,
    get_user_by_id,
    get_pin_hash,
    set_password,
    set_pin,
    set_recovery,
    start_email_change,
    confirm_email,
    legacy_key,
    adopt_user_key,
    rate_limit_remaining,
    rate_limit_fail,
    rate_limit_reset,
    rate_limit_sweep,
    record_event,
    events_for_user,
)
from crypto import (
    new_key_material,
    unwrap_vault_key,
    rewrap_vault_key,
    new_recovery_code,
    normalize_recovery_code,
    hash_secret,
    verify_secret,
    secret_too_long,
    BCRYPT_MAX_BYTES,
)
from mailer import send_email, smtp_configured, recovery_email_body, RECOVERY_SUBJECT
from cryptography.fernet import InvalidToken
import hashlib
import os
import secrets
import time
import threading
from datetime import timedelta
from functools import wraps
from dotenv import load_dotenv
from pathlib import Path

app = Flask(__name__)


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR.parent / ".env")

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("Missing secret key in .env")

app.secret_key = SECRET_KEY

AUTO_LOCK_MINUTES = int(os.getenv("AUTO_LOCK_MINUTES", "15"))
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "12"))
MIN_PIN_LENGTH = int(os.getenv("MIN_PIN_LENGTH", "6"))
EMAIL_TOKEN_HOURS = int(os.getenv("EMAIL_TOKEN_HOURS", "24"))

# One switch rather than several that could be set inconsistently: it makes
# the session cookie HTTPS-only and turns on HSTS. Must be 1 anywhere the app
# is reachable over a network.
PRODUCTION = os.getenv("PRODUCTION", "0") == "1"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=AUTO_LOCK_MINUTES),
    # Nothing this app accepts is large. Werkzeug rejects a bigger body before
    # it is read into memory.
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", str(64 * 1024))),
)

# Per-field ceilings, applied by json_fields. A password field is generous
# because a stored vault entry may legitimately be a long passphrase; the
# account password itself is capped separately by bcrypt's 72-byte limit.
FIELD_LIMITS = {
    "site": 255,
    "username": 255,
    "password": 1024,
    "pin": 64,
    "email": 254,
    "current_password": 1024,
    "new_password": 1024,
    "new_pin": 64,
}
DEFAULT_FIELD_LIMIT = 255

# Compared against when a username does not exist, so that a failed login
# costs the same time either way and cannot be used to enumerate usernames.
DUMMY_PASSWORD_HASH = hash_secret("no such user")

# ---------- PIN brute-force protection ----------
# Tracked per user in module state rather than in the session: the session is
# a signed cookie, so an attacker holding one could replay an older copy to
# reset a counter stored there.

PIN_MAX_ATTEMPTS = int(os.getenv("PIN_MAX_ATTEMPTS", "5"))
PIN_LOCKOUT_SECONDS = int(os.getenv("PIN_LOCKOUT_SECONDS", "300"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "300"))

# "pin" is keyed by user id, "login" by the submitted username - a username
# that does not exist gets counted too, so failures cost the same either way.
# Note this lets someone lock a real user out by failing on purpose; on a
# single-machine app that is academic, but it is the trade being made.
LIMITS = {
    "pin": (PIN_MAX_ATTEMPTS, PIN_LOCKOUT_SECONDS),
    "login": (LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_SECONDS),
}

# Counters live in the database, not module state: they must be shared by
# every thread and process and must survive a restart, or an attacker just
# waits for a reload. Wall clock rather than monotonic, because the value is
# compared across processes.

def lockout_remaining(scope, key):
    """Seconds left on this lockout, or 0 if attempts are allowed."""
    return rate_limit_remaining(scope, str(key), time.time())


def register_failure(scope, key):
    """Count a failed attempt. Returns attempts left, or 0 once locked out."""
    max_attempts, lockout_seconds = LIMITS[scope]

    return rate_limit_fail(scope, str(key), max_attempts, lockout_seconds, time.time())


def register_success(scope, key):
    rate_limit_reset(scope, str(key))


def json_fields(*names):
    """Pull required non-empty string fields from the body.

    Returns (values, None) or (None, error_response).
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None, ({"error": "Expected a JSON object"}, 400)

    values = []

    for name in names:
        value = data.get(name)

        if not isinstance(value, str) or not value.strip():
            return None, ({"error": f"Missing or empty field: {name}"}, 400)

        limit = FIELD_LIMITS.get(name, DEFAULT_FIELD_LIMIT)

        if len(value) > limit:
            return None, ({"error": f"{name} must be at most {limit} characters"}, 400)

        values.append(value)

    return values, None


# ---------- Vault keys held in server memory ----------
# The session cookie is signed but NOT encrypted - Flask base64s the payload
# and anyone holding the cookie can read it. A decryption key put there would
# be handed straight to whoever stole the cookie, so the cookie carries only
# an opaque handle and the key itself never leaves this process.
#
# Consequence: restarting the server drops every key and everyone must log in
# again. Under debug=True that happens on every .py save.

_vault_keys = {}
_vault_keys_lock = threading.Lock()


def _prune_vault_keys(now):
    """Drop keys idle longer than the session lifetime. Caller holds the lock."""
    ttl = AUTO_LOCK_MINUTES * 60

    for token in [t for t, entry in _vault_keys.items() if now - entry["touched"] > ttl]:
        del _vault_keys[token]


def remember_vault_key(key, user_id):
    """Hold a vault key and return the handle to put in the session."""
    token = secrets.token_urlsafe(32)
    now = time.monotonic()

    with _vault_keys_lock:
        _prune_vault_keys(now)
        _vault_keys[token] = {"key": key, "user_id": user_id, "touched": now}

    return token


def current_vault_key():
    token = session.get("vault_token")

    if not token:
        return None

    now = time.monotonic()

    with _vault_keys_lock:
        _prune_vault_keys(now)
        entry = _vault_keys.get(token)

        if entry is None:
            return None

        entry["touched"] = now

        return entry["key"]


def forget_vault_key():
    token = session.get("vault_token")

    if token:
        with _vault_keys_lock:
            _vault_keys.pop(token, None)


def forget_other_vault_keys(user_id, keep_token):
    """Drop every held key for this user except the caller's own.

    Invalidating their sessions stops them authenticating; dropping their keys
    means the plaintext is gone from memory too, rather than lingering until
    the idle timeout.
    """
    with _vault_keys_lock:
        for token in [
            t for t, entry in _vault_keys.items()
            if entry.get("user_id") == user_id and t != keep_token
        ]:
            del _vault_keys[token]


# ---------- CSRF ----------
# Double-submit against the signed session: the token lives in the session
# cookie and must be echoed back in a form field or header. An attacker on
# another origin can cause the cookie to be sent but cannot read it, so they
# cannot produce a matching token.

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def csrf_token():
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def enforce_csrf():
    if request.method in SAFE_METHODS:
        return None

    expected = session.get("csrf_token", "")
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")

    if not expected or not secrets.compare_digest(sent, expected):
        if request.is_json:
            return {"error": "Invalid or missing CSRF token"}, 400

        abort(400)

    return None


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    )

    if PRODUCTION:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )

    return response


# ---------- Auth helpers ----------

def current_user_id():
    return session.get("user_id")


def session_user():
    """The signed-in user, or None if the session is no longer valid.

    A session carries the token_version it saw at login. Changing a password
    bumps that number, so sessions issued before the change stop matching and
    are refused here - which is the only way to log other devices out when
    sessions are stateless signed cookies.
    """
    user_id = session.get("user_id")

    if not user_id:
        return None

    user = get_user_by_id(user_id)

    if user is None or session.get("token_version") != user["token_version"]:
        return None

    return user


def login_required(view):
    """Page routes: send anonymous visitors to the login screen."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session_user() is None:
            session.clear()
            return redirect("/login")

        return view(*args, **kwargs)

    return wrapper


def api_login_required(view):
    """JSON routes: answer with 401 rather than an HTML redirect."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session_user() is None:
            session.clear()
            return {"error": "Unauthorized"}, 401

        return view(*args, **kwargs)

    return wrapper


def vault_key_required(view):
    """Routes that encrypt or decrypt. The key lives in memory, so it can be
    gone while the session cookie is still valid - after a server restart."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_vault_key() is None:
            return {"error": "Vault locked. Log in again."}, 401

        return view(*args, **kwargs)

    return wrapper


init_db()
rate_limit_sweep(time.time())


def check_deployment():
    """Warn at startup about configurations that are unsafe on a network."""
    if not PRODUCTION:
        app.logger.warning(
            "PRODUCTION=0: the session cookie is not marked Secure and HSTS is "
            "off. Set PRODUCTION=1 for anything reachable over a network."
        )

    if PRODUCTION and not smtp_configured():
        app.logger.warning(
            "PRODUCTION=1 but SMTP is not configured - recovery codes and email "
            "confirmations cannot be delivered."
        )

    if legacy_key() is not None:
        app.logger.warning(
            "key.txt is still present. It decrypts every entry written before "
            "per-user keys. Delete it once every account has logged in once, and "
            "never copy it onto a server."
        )


check_deployment()


def email_token_pair():
    """A verification token and the hash of it that is what gets stored."""
    token = secrets.token_urlsafe(32)

    return token, hashlib.sha256(token.encode()).hexdigest()


def send_email_verification(user, email):
    """Park the address as pending and send it a confirmation link.

    Returns (link, sent, detail). The link is returned so it can be shown when
    mail cannot be delivered, which is the only way to finish on a box with no
    SMTP configured.
    """
    token, token_hash = email_token_pair()
    expires = time.time() + EMAIL_TOKEN_HOURS * 3600

    start_email_change(user["id"], email, token_hash, expires)

    link = url_for("verify_email", user_id=user["id"], token=token, _external=True)

    sent, detail = send_email(
        email,
        "Confirm your recovery address",
        f"""Confirm this address so it can receive vault recovery codes.

    Account: {user['username']}
    Link:    {link}

The link expires in {EMAIL_TOKEN_HOURS} hours. If you did not ask for this,
ignore it - nothing changes until the link is opened.
""",
    )

    record_event("email_change_requested", user["id"], user["username"], email)

    return link, sent, detail


def issue_recovery_code(user_id, username, email, vault_key):
    """Mint a recovery code, store only what it unwraps, and try to deliver it.

    Returns (code, sent, detail). The code is returned so the caller can show
    it when delivery failed - a code that was generated but never reached the
    user would leave that vault wrapped under a secret nobody holds.
    """
    code = new_recovery_code()
    salt, wrapped = rewrap_vault_key(vault_key, normalize_recovery_code(code))

    set_recovery(user_id, salt, wrapped)
    record_event("recovery_code_issued", user_id, username)

    sent, detail = send_email(
        email,
        RECOVERY_SUBJECT,
        recovery_email_body(username, code),
    )

    if not sent:
        app.logger.warning("recovery code for %r not delivered: %s", username, detail)

    return code, sent, detail


def unlock_vault_key(user, password):
    """Recover this user's vault key, migrating them onto one if they predate it.

    A user created before per-user keys has no wrapped_key: their entries are
    still under the shared key.txt. Their first login after this change moves
    them across, which is the only moment their password is available to do it.
    """
    if user["wrapped_key"] is None:
        vault_key, salt, wrapped = new_key_material(password)
        moved = adopt_user_key(user["id"], legacy_key(), vault_key, salt, wrapped)
        app.logger.info("migrated %r onto its own key (%d entries)", user["username"], moved)

        return vault_key

    return unwrap_vault_key(password, user["kdf_salt"], user["wrapped_key"])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")

        locked_for = lockout_remaining("login", username)

        if locked_for:
            return render_template(
                "login.html",
                error=f"Too many attempts. Try again in {locked_for}s."
            )

        user = get_user_by_username(username)

        if user is None:
            # Spend the same time as a real check before failing.
            verify_secret(password, DUMMY_PASSWORD_HASH)
        elif verify_secret(password, user["password_hash"]):
            register_success("login", username)

            try:
                vault_key = unlock_vault_key(user, password)
            except (InvalidToken, RuntimeError) as problem:
                app.logger.error("vault key unlock failed for %r: %s", username, problem)
                return render_template("login.html", error="Could not unlock the vault")

            # Start from an empty session so nothing an anonymous visitor
            # planted there survives into an authenticated one.
            session.clear()
            session.permanent = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            session["user_id"] = user["id"]
            session["token_version"] = user["token_version"]
            session["vault_token"] = remember_vault_key(vault_key, user["id"])

            record_event("login", user["id"], user["username"])

            # A user who predates recovery codes gets one the first time they
            # log in with an address on file - this is the only moment their
            # vault key is available to wrap.
            if (
                user["recovery_wrapped_key"] is None
                and user["email"]
                and (user["email_verified"] or not smtp_configured())
            ):
                issue_recovery_code(user["id"], user["username"], user["email"], vault_key)

            return redirect("/")

        attempts_left = register_failure("login", username)
        record_event("login_failed", user["id"] if user else None, username)

        if not attempts_left:
            record_event("login_locked_out", user["id"] if user else None, username)
            return render_template(
                "login.html",
                error=f"Too many attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s."
            )

        return render_template("login.html", error="Invalid login")

    return render_template("login.html")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method != "POST":
        return render_template("forgot_password.html")

    username = request.form.get("username", "")
    code = request.form.get("code", "")
    new_password = request.form.get("new_password", "")

    locked_for = lockout_remaining("login", username)

    if locked_for:
        return render_template(
            "forgot_password.html",
            error=f"Too many attempts. Try again in {locked_for}s."
        )

    if len(new_password) < MIN_PASSWORD_LENGTH:
        return render_template(
            "forgot_password.html",
            error=f"New password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    if secret_too_long(new_password):
        return render_template(
            "forgot_password.html",
            error=f"New password must be at most {BCRYPT_MAX_BYTES} bytes"
        )

    user = get_user_by_username(username)

    # One message for every failure: a wrong code, an unknown user and an
    # account with no recovery set up must be indistinguishable.
    failure = "That username and recovery code did not match"

    if user is None or user["recovery_wrapped_key"] is None:
        register_failure("login", username)
        return render_template("forgot_password.html", error=failure)

    try:
        vault_key = unwrap_vault_key(
            normalize_recovery_code(code),
            user["recovery_salt"],
            user["recovery_wrapped_key"],
        )
    except (InvalidToken, ValueError, TypeError):
        attempts_left = register_failure("login", username)

        if not attempts_left:
            return render_template(
                "forgot_password.html",
                error=f"Too many attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s."
            )

        return render_template("forgot_password.html", error=failure)

    register_success("login", username)
    record_event("password_reset_via_recovery_code", user["id"], username)

    salt, wrapped = rewrap_vault_key(vault_key, new_password)
    password_hash = hash_secret(new_password)
    set_password(user["id"], password_hash, salt, wrapped)

    # The used code is spent: issue and send a replacement.
    code, sent, detail = issue_recovery_code(
        user["id"], user["username"], user["email"], vault_key
    )

    return render_template(
        "forgot_password.html",
        done=True,
        new_code=None if sent else code,
        delivery_problem=None if sent else detail,
    )


@app.route("/verify_email/<int:user_id>")
def verify_email(user_id):
    token = request.args.get("token", "")

    if not token:
        return render_template("verify_email.html", ok=False)

    confirmed = confirm_email(
        user_id, hashlib.sha256(token.encode()).hexdigest(), time.time()
    )

    if confirmed is None:
        record_event("email_verify_failed", user_id)
        return render_template("verify_email.html", ok=False)

    record_event("email_verified", user_id, detail=confirmed)

    return render_template("verify_email.html", ok=True, email=confirmed)


@app.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")

    forget_vault_key()
    session.clear()

    if user_id:
        record_event("logout", user_id)

    return redirect("/login")


@app.route("/")
@login_required
def home():
    return render_template("home.html")


@app.route("/generator")
@login_required
def generator():
    return render_template("generator.html")

@app.route("/vault")
@login_required
def vault():
    return render_template("vault.html")

# Rendered rather than raw, so the page reads as history instead of a log dump.
EVENT_LABELS = {
    "login": "Signed in",
    "login_failed": "Failed sign-in attempt",
    "login_locked_out": "Locked out after repeated failures",
    "logout": "Signed out",
    "password_changed": "Password changed",
    "pin_changed": "Reveal PIN changed",
    "email_change_requested": "Recovery address change requested",
    "email_verified": "Recovery address confirmed",
    "email_verify_failed": "Invalid confirmation link used",
    "recovery_code_issued": "Recovery code issued",
    "password_reset_via_recovery_code": "Password reset with a recovery code",
    "entry_deleted": "Vault entry deleted",
}

ACTIVITY_LIMIT = int(os.getenv("ACTIVITY_LIMIT", "50"))


@app.route("/activity")
@login_required
def activity():
    user = get_user_by_id(current_user_id())

    if user is None:
        return redirect("/logout")

    events = [
        {
            "at": event["at"],
            "label": EVENT_LABELS.get(event["event"], event["event"].replace("_", " ")),
            "detail": event["detail"],
            "concerning": event["event"] in ("login_failed", "login_locked_out", "email_verify_failed"),
        }
        for event in events_for_user(user["id"], ACTIVITY_LIMIT)
    ]

    return render_template("activity.html", events=events, limit=ACTIVITY_LIMIT)


@app.route("/settings")
@login_required
def settings():
    user = get_user_by_id(current_user_id())

    if user is None:
        return redirect("/logout")

    return render_template(
        "settings.html",
        username=user["username"],
        email=user["email"] or "",
        email_verified=user["email_verified"],
        pending_email=user["pending_email"],
        auto_lock_minutes=AUTO_LOCK_MINUTES,
        has_recovery=user["recovery_wrapped_key"] is not None,
        smtp_ready=smtp_configured(),
    )


@app.route("/set_email", methods=["POST"])
@api_login_required
def set_email_route():
    fields, error = json_fields("current_password", "email")

    if error:
        return error

    current_password, email = fields

    user = get_user_by_id(current_user_id())

    if user is None:
        return {"error": "Unauthorized"}, 401

    locked_for = lockout_remaining("login", user["username"])

    if locked_for:
        return {"error": f"Too many attempts. Try again in {locked_for}s."}, 429

    # This address is where recovery codes go, so it decides who can take the
    # account over. Changing it needs the password, not just a live session.
    if not verify_secret(current_password, user["password_hash"]):
        attempts_left = register_failure("login", user["username"])

        if not attempts_left:
            return {"error": f"Too many attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s."}, 429

        return {"error": "Password is incorrect", "attempts_left": attempts_left}, 403

    if "@" not in email:
        return {"error": "That does not look like an email address"}, 400

    register_success("login", user["username"])

    link, sent, detail = send_email_verification(user, email.strip())

    if sent:
        return {"message": f"Confirm the address: a link has been sent to {email.strip()}"}

    # Nothing was delivered, so the link has to be shown or the address can
    # never be confirmed on a server with no mail configured.
    return {
        "message": "Could not send the confirmation email, so open this link yourself:",
        "link": link,
        "detail": detail,
    }


@app.route("/send_recovery_code", methods=["POST"])
@api_login_required
@vault_key_required
def send_recovery_code_route():
    fields, error = json_fields("current_password")

    if error:
        return error

    current_password, = fields

    user = get_user_by_id(current_user_id())

    if user is None:
        return {"error": "Unauthorized"}, 401

    locked_for = lockout_remaining("login", user["username"])

    if locked_for:
        return {"error": f"Too many attempts. Try again in {locked_for}s."}, 429

    # Requires the password so that an unattended logged-in screen cannot be
    # used to mint a code and mail it somewhere else.
    if not verify_secret(current_password, user["password_hash"]):
        attempts_left = register_failure("login", user["username"])

        if not attempts_left:
            return {"error": f"Too many attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s."}, 429

        return {"error": "Password is incorrect", "attempts_left": attempts_left}, 403

    if not user["email"]:
        return {"error": "Save an email address first"}, 400

    if not user["email_verified"] and smtp_configured():
        return {
            "error": "Confirm your email address first - a code sent to an "
                     "unconfirmed address could be going to the wrong person."
        }, 400

    register_success("login", user["username"])

    code, sent, detail = issue_recovery_code(
        user["id"], user["username"], user["email"], current_vault_key()
    )

    if sent:
        return {"message": f"A new recovery code has been sent to {user['email']}"}

    # Delivery failed, so the code has to be shown - it is the only copy.
    return {
        "message": "Could not send the email, so here is the code. Save it now, it is not stored.",
        "code": code,
        "detail": detail,
    }


@app.route("/change_password", methods=["POST"])
@api_login_required
@vault_key_required
def change_password_route():
    fields, error = json_fields("current_password", "new_password")

    if error:
        return error

    current_password, new_password = fields

    user = get_user_by_id(current_user_id())

    if user is None:
        return {"error": "Unauthorized"}, 401

    # Shares the login lockout: this endpoint checks the same secret, so
    # without it a stolen session would be an unlimited password oracle.
    locked_for = lockout_remaining("login", user["username"])

    if locked_for:
        return {"error": f"Too many attempts. Try again in {locked_for}s."}, 429

    if not verify_secret(current_password, user["password_hash"]):
        attempts_left = register_failure("login", user["username"])

        if not attempts_left:
            return {"error": f"Too many attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s."}, 429

        return {"error": "Current password is incorrect", "attempts_left": attempts_left}, 403

    if len(new_password) < MIN_PASSWORD_LENGTH:
        return {"error": f"New password must be at least {MIN_PASSWORD_LENGTH} characters"}, 400

    if secret_too_long(new_password):
        return {"error": f"New password must be at most {BCRYPT_MAX_BYTES} bytes"}, 400

    register_success("login", user["username"])

    # The vault key is unchanged - only its wrapping is redone, so no entry
    # needs re-encrypting.
    salt, wrapped = rewrap_vault_key(current_vault_key(), new_password)
    password_hash = hash_secret(new_password)

    token_version = set_password(user["id"], password_hash, salt, wrapped)

    # Every other session was issued against the old token_version and stops
    # validating now; this one is carried forward so the user stays put.
    session["token_version"] = token_version
    forget_other_vault_keys(user["id"], session.get("vault_token"))

    record_event("password_changed", user["id"], user["username"])

    return {"message": "Password changed. Other sessions have been signed out."}


@app.route("/change_pin", methods=["POST"])
@api_login_required
def change_pin_route():
    fields, error = json_fields("current_password", "new_pin")

    if error:
        return error

    current_password, new_pin = fields

    user = get_user_by_id(current_user_id())

    if user is None:
        return {"error": "Unauthorized"}, 401

    locked_for = lockout_remaining("login", user["username"])

    if locked_for:
        return {"error": f"Too many attempts. Try again in {locked_for}s."}, 429

    # Deliberately the password, not the old PIN: the PIN is a second factor,
    # so forgetting it should be recoverable by the account owner.
    if not verify_secret(current_password, user["password_hash"]):
        attempts_left = register_failure("login", user["username"])

        if not attempts_left:
            return {"error": f"Too many attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s."}, 429

        return {"error": "Password is incorrect", "attempts_left": attempts_left}, 403

    if len(new_pin) < MIN_PIN_LENGTH:
        return {"error": f"PIN must be at least {MIN_PIN_LENGTH} characters"}, 400

    if secret_too_long(new_pin):
        return {"error": f"PIN must be at most {BCRYPT_MAX_BYTES} bytes"}, 400

    register_success("login", user["username"])

    set_pin(user["id"], hash_secret(new_pin))

    record_event("pin_changed", user["id"], user["username"])

    return {"message": "PIN changed"}

@app.route("/generate")
@api_login_required
def generate():
    length = request.args.get("length", default=16, type=int)
    return make_password(length)

@app.route("/store", methods=["POST"])
@api_login_required
@vault_key_required
def store():
    fields, error = json_fields("site", "username", "password")

    if error:
        return error

    site, username, password = fields

    store_entry(current_user_id(), site, username, password, current_vault_key())

    return {"message": "Stored successfully"}

@app.route("/get_entries")
@api_login_required
def get_entries_route():
    site = request.args.get("site", "")
    username = request.args.get("username", "")

    entries = get_entries(current_user_id(), site, username)

    return jsonify(entries)

@app.route("/get_entry/<int:entry_id>")
@api_login_required
def get_entry_route(entry_id):
    entry = get_entry_meta_by_id(entry_id, current_user_id())

    if entry is None:
        return {"error": "Entry not found"}, 404

    return jsonify(entry)

@app.route("/reveal_password/<int:entry_id>", methods=["POST"])
@api_login_required
@vault_key_required
def reveal_password_route(entry_id):
    user_id = current_user_id()

    locked_for = lockout_remaining("pin", user_id)

    if locked_for:
        return {"error": f"Too many attempts. Try again in {locked_for}s."}, 429

    fields, error = json_fields("pin")

    if error:
        return error

    pin, = fields

    pin_hash = get_pin_hash(user_id)

    if pin_hash is None:
        return {"error": "Unauthorized"}, 401

    if not verify_secret(pin, pin_hash):
        attempts_left = register_failure("pin", user_id)

        if not attempts_left:
            return {"error": f"Too many attempts. Try again in {PIN_LOCKOUT_SECONDS}s."}, 429

        return {"error": "Invalid PIN", "attempts_left": attempts_left}, 403

    register_success("pin", user_id)

    entry = get_entry_by_id(entry_id, user_id, current_vault_key())

    if entry is None:
        return {"error": "Entry not found"}, 404

    return {"password": entry["password"]}

@app.route("/update_entry/<int:entry_id>", methods=["POST"])
@api_login_required
@vault_key_required
def update_entry_route(entry_id):
    fields, error = json_fields("site", "username", "password")

    if error:
        return error

    site, username, password = fields

    changed = update_entry(
        entry_id,
        current_user_id(),
        site,
        username,
        password,
        current_vault_key()
    )

    if not changed:
        return {"error": "Entry not found"}, 404

    return {"message": "Entry updated"}

@app.route("/delete_entry/<int:entry_id>", methods=["POST"])
@api_login_required
def delete_entry_route(entry_id):
    if not delete_entry(entry_id, current_user_id()):
        return {"error": "Entry not found"}, 404

    record_event("entry_deleted", current_user_id(), detail=f"entry {entry_id}")

    return {"message": "Entry deleted"}

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5001"))

    # The Werkzeug debugger is remote code execution for anyone who can reach
    # it, so it must never be served on anything but the loopback interface.
    if debug and host not in ("127.0.0.1", "localhost"):
        raise RuntimeError(
            f"Refusing to start the debugger on {host}. Set FLASK_DEBUG=0 to bind a non-local interface."
        )

    app.run(debug=debug, host=host, port=port)
