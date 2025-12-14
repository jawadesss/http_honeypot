from flask import Flask, request, abort, send_from_directory
from detector import detect_attack
from logger import log_event
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    static_url_path='/assets',
    static_folder='assets'
)

@app.before_request
def inspect_request():
    attack, severity, explanation = detect_attack(request)
    log_event(request, attack, severity, explanation)

@app.route("/", methods=["GET"])
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login", methods=["POST"])
def login():
    # Always fail (honeypot)
    return "Invalid username or password", 401

@app.route("/admin")
def admin():
    abort(403)

@app.errorhandler(404)
def not_found(e):
    return "Not Found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
