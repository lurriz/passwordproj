from flask import Flask, render_template
from flask import request
from passGenerator import make_password

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/generate")
def generate():
    return make_password()
    

if __name__ == "__main__":
    app.run(debug=True, port =5001)