from flask import Flask, render_template, request, jsonify, redirect, session
from pass_generator import make_password
from db import init_db, store_entry, get_entries, get_entry_by_id, update_entry, delete_entry
import bcrypt
import secrets
import os
from dotenv import load_dotenv
from pathlib import Path

app = Flask(__name__)


app.secret_key = secrets.token_hex(32)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR.parent / ".env")

LOGIN_USERNAME = os.getenv("LOGIN_USERNAME")
LOGIN_PASSWORD_HASH = os.getenv("LOGIN_PASSWORD_HASH")

if not LOGIN_USERNAME or not LOGIN_PASSWORD_HASH:
    raise RuntimeError("Missing login credentials in .env")

REVEAL_PIN_HASH = os.getenv("REVEAL_PIN_HASH")

if not REVEAL_PIN_HASH:
    raise RuntimeError("Missing reveal PIN hash in .env")

init_db()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")

        if username == LOGIN_USERNAME and bcrypt.checkpw(
            password.encode(),
            LOGIN_PASSWORD_HASH.encode()
        ):
            session["logged_in"] = True
            return redirect("/")

        return render_template("login.html", error="Invalid login")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect("/login")

    return render_template("index.html")

@app.route("/vault")
def vault():
    if not session.get("logged_in"):
        return redirect("/login")

    return render_template("vault.html")

@app.route("/settings")
def settings():
    if not session.get("logged_in"):
        return redirect("/login")

    return render_template("settings.html")

@app.route("/generate")
def generate():
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    length = request.args.get("length", default=16, type=int)
    return make_password(length)

@app.route("/store", methods=["POST"])
def store():
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    data = request.get_json()
    store_entry(data["site"], data["username"], data["password"])

    return {"message": "Stored successfully"}

@app.route("/get_entries")
def get_entries_route():
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    site = request.args.get("site", "")
    username = request.args.get("username", "")

    entries = get_entries(site, username)

    return jsonify(entries)

@app.route("/get_entry/<int:entry_id>")
def get_entry_route(entry_id):
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    entry = get_entry_by_id(entry_id)

    if entry is None:
        return {"error": "Entry not found"}, 404

    return jsonify(entry)

@app.route("/reveal_password/<int:entry_id>", methods=["POST"])
def reveal_password_route(entry_id):
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    data = request.get_json()
    pin = data.get("pin", "")

    if not bcrypt.checkpw(pin.encode(), REVEAL_PIN_HASH.encode()):
        return {"error": "Invalid PIN"}, 403

    entry = get_entry_by_id(entry_id)

    if entry is None:
        return {"error": "Entry not found"}, 404

    return {"password": entry["password"]}

@app.route("/update_entry/<int:entry_id>", methods=["POST"])
def update_entry_route(entry_id):
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    data = request.get_json()

    update_entry(
        entry_id,
        data["site"],
        data["username"],
        data["password"]
    )

    return {"message": "Entry updated"}

@app.route("/delete_entry/<int:entry_id>", methods=["POST"])
def delete_entry_route(entry_id):
    if not session.get("logged_in"):
        return {"error": "Unauthorized"}, 401

    delete_entry(entry_id)

    return {"message": "Entry deleted"}

if __name__ == "__main__":
    app.run(debug=True,  port=5001)

##app.run(debug=False, host="vmware network adapter ip", port=5001)