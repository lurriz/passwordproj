from flask import Flask, render_template, request, jsonify
from pass_generator import make_password
from db import store_entry, get_entries


app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/vault")
def vault():
    return render_template("vault.html")

@app.route("/generate")
def generate():
    length = request.args.get("length", default=16, type=int)
    return make_password(length)

@app.route("/store", methods=["POST"])
def store():
    data = request.get_json()

    store_entry(data["site"], data["username"], data["password"])

    return {"message": "Stored successfully"}

@app.route("/get_entries")
def get_entries_route():
    entries = get_entries()
    return jsonify(entries)

if __name__ == "__main__":
    app.run(debug=True, port=5001)