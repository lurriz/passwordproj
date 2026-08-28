"""Outbound email, used only to deliver recovery codes.

Configured entirely from .env. When SMTP is not configured, send_email reports
failure rather than raising - every caller must then surface the code some
other way, because a recovery code that was generated but never delivered
would leave the vault wrapped under a secret nobody has.
"""

import os
import smtplib
import ssl
from email.message import EmailMessage

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "1") == "1"


def smtp_configured():
    return bool(SMTP_HOST and SMTP_FROM)


def send_email(to, subject, body):
    """Returns (sent, detail). Never raises - delivery is best effort."""
    if not smtp_configured():
        return False, "SMTP is not configured (set SMTP_HOST and SMTP_FROM in .env)"

    if not to:
        return False, "no address on file"

    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            if SMTP_STARTTLS:
                smtp.starttls(context=ssl.create_default_context())

            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASSWORD)

            smtp.send_message(message)
    except Exception as problem:
        return False, f"{type(problem).__name__}: {problem}"

    return True, "sent"


RECOVERY_SUBJECT = "Your vault recovery code"


def recovery_email_body(username, code):
    return f"""Keep this somewhere safe. It is the only way back into your vault
if you forget your password, and it replaces any code you were sent before.

    Account:       {username}
    Recovery code: {code}

Nobody can recover your vault without it, including whoever runs this server -
the code itself is not stored anywhere.
"""
