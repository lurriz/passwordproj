from flask import Flask, render_template, request, jsonify, redirect, session
from pass_generator import make_password
from db import store_entry, get_entries, get_entry_by_id, init_db
import bcrypt
import secrets

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

LOGIN_USERNAME = "adm"
LOGIN_PASSWORD_HASH = bcrypt.hashpw("1234".encode(), bcrypt.gensalt())

init_db()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == LOGIN_USERNAME and bcrypt.checkpw(password.encode(), LOGIN_PASSWORD_HASH):
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

if __name__ == "__main__":
    app.run(debug=True, port=5001)