# routes/posts.py - Blog post routes
# WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

import sqlite3
import requests
from flask import Blueprint, request, jsonify

posts_bp = Blueprint("posts", __name__)

DATABASE = "blog.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


@posts_bp.route("/search")
def search_posts():
    keyword = request.args.get("q", "")
    # CWE-89: SQL Injection — keyword concatenated directly into SQL query string
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT id, title, body FROM posts WHERE title LIKE '%" + keyword + "%'"
    cursor.execute(query)
    posts = cursor.fetchall()
    conn.close()
    return jsonify(posts)


@posts_bp.route("/<int:post_id>")
def get_post(post_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    post = cursor.fetchone()
    conn.close()
    if not post:
        return jsonify({"error": "Not found"}), 404
    return jsonify(post)


@posts_bp.route("/preview-image")
def preview_image():
    image_url = request.args.get("url", "")
    # CWE-918: SSRF — user-supplied URL fetched server-side without validation
    response = requests.get(image_url, timeout=10)
    return response.content, 200, {"Content-Type": "image/jpeg"}


@posts_bp.route("/", methods=["POST"])
def create_post():
    data = request.get_json()
    title = data.get("title", "")
    body = data.get("body", "")
    author_id = data.get("author_id", 1)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO posts (title, body, author_id) VALUES (?, ?, ?)",
        (title, body, author_id),
    )
    conn.commit()
    post_id = cursor.lastrowid
    conn.close()
    return jsonify({"id": post_id}), 201
