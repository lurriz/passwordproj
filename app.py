from flask import Flask, render_template, request
from passGenerator import make_password

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/generate")
def generate():
    length = request.args.get("length", default=16, type=int)
    return make_password(length)

if __name__ == "__main__":
    app.run(debug=True, port=5001)