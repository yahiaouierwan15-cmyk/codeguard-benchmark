# routes/auth.py - Authentication routes
# WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

import hashlib
import sqlite3
from flask import Blueprint, request, jsonify

auth_bp = Blueprint("auth", __name__)

# CWE-798: Hardcoded API key used for token signing
API_SECRET_KEY = "blogapi-secret-key-do-not-share-2024"

DATABASE = "blog.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    # CWE-328: Weak hashing algorithm — MD5 used for password storage
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed),
        )
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already taken"}), 409
    conn.close()
    return jsonify({"id": user_id, "username": username}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    # CWE-328: Weak hashing — MD5 comparison
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username FROM users WHERE username = ? AND password_hash = ?",
        (username, hashed),
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    # Return token built from hardcoded secret
    import hmac
    token = hmac.new(API_SECRET_KEY.encode(), username.encode(), hashlib.sha256).hexdigest()
    return jsonify({"token": token, "user_id": user[0]})
