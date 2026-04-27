"""Path traversal trigger — VP-006 (CWE-22)."""
from flask import request


def vuln_open():
    fname = request.args.get("file", "")
    with open(fname, "r") as f:
        return f.read()


def vuln_join():
    base = "/var/www/uploads"
    fname = request.args.get("name", "")
    path = base + "/" + fname
    with open(path) as f:
        return f.read()
