# app.py - Blog platform REST API entry point
# WARNING: This app intentionally contains security vulnerabilities for benchmark testing.

from flask import Flask
from routes.posts import posts_bp
from routes.auth import auth_bp

app = Flask(__name__)

app.register_blueprint(posts_bp, url_prefix="/posts")
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.route("/health")
def health():
    return {"status": "ok", "service": "blog-api"}


if __name__ == "__main__":
    app.run(debug=True, port=5001)
