"""SQL injection trigger — VP-003 (CWE-89)."""
import sqlite3
from flask import request


def vuln_format_string():
    user = request.args.get("user", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % user
    cur.execute(query)
    return cur.fetchall()


def vuln_concat():
    uid = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return cur.fetchall()
