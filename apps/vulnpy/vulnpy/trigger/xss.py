"""Reflected XSS trigger — VP-004 (CWE-79)."""
from flask import request, make_response


def vuln_reflected():
    name = request.args.get("name", "anonymous")
    html = "<h1>Hello, " + name + "!</h1>"
    return make_response(html)


def vuln_render():
    msg = request.args.get("msg", "")
    return "<div>" + msg + "</div>"
