"""Production entrypoint.

Runs the app under waitress, which is a real WSGI server, unlike the Werkzeug
development server that app.py starts.

    PRODUCTION=1 python serve.py

ONE PROCESS ONLY. Vault keys are held in this process's memory and deliberately
never written anywhere - putting them in Redis or a table would place each
user's decryption key beside the ciphertext it protects, which is the whole
thing per-user encryption exists to prevent. Threads share that memory, so
scale with THREADS; a second *process* would hand users a worker that does not
hold their key and lock them out at random.
"""

import os
import sys

from waitress import serve

from app import app

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "5001"))
THREADS = int(os.getenv("THREADS", "8"))

if __name__ == "__main__":
    if os.getenv("PRODUCTION", "0") != "1":
        print("Refusing to serve without PRODUCTION=1.", file=sys.stderr)
        print("Without it the session cookie is not marked Secure.", file=sys.stderr)
        raise SystemExit(1)

    print(f"serving on {HOST}:{PORT} with {THREADS} threads (single process)")

    serve(app, host=HOST, port=PORT, threads=THREADS, url_scheme="https")
