# app.py - Vulnerable Flask application (for security testing purposes)
# This app intentionally contains security vulnerabilities for benchmark testing.

import os
import subprocess
import sqlite3
from flask import Flask, request, jsonify, send_file
import requests

app = Flask(__name__)

DATABASE = "users.db"
SECRET_KEY = "mysupersecretkey123"  # CWE-798: Hardcoded secret


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


@app.route("/users")
def get_users():
    name = request.args.get("name", "")
    # CWE-89: SQL Injection - user input concatenated directly into query
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    users = cursor.fetchall()
    conn.close()
    return jsonify(users)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: Command Injection - user input passed directly to shell
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output.decode()


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # CWE-918: SSRF - user-controlled URL fetched server-side
    response = requests.get(url)
    return response.text


@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # CWE-22: Path Traversal - user input joined to base path without sanitization
    base_dir = "/var/app/uploads"
    filepath = os.path.join(base_dir, filename)
    return send_file(filepath)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    # CWE-89: SQL Injection (login bypass) - f-string interpolation into SQL
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"status": "ok", "token": "hardcoded-jwt-token"})
    return jsonify({"status": "error"}), 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # CWE-89: SQL Injection - string concatenation in LIKE query
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM articles WHERE title LIKE '%" + term + "%'")
    results = cursor.fetchall()
    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True)
