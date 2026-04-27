"""SSRF trigger — VP-007 (CWE-918)."""
import requests
from flask import request as flask_request


def vuln_requests_get():
    url = flask_request.args.get("url", "https://example.com")
    resp = requests.get(url)
    return resp.text


def vuln_urlopen():
    from urllib.request import urlopen
    target = flask_request.args.get("target", "")
    return urlopen(target).read()
