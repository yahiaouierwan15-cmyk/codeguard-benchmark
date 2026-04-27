"""Insecure deserialization trigger — VP-002 (CWE-502)."""
import pickle
import yaml
from flask import request


def vuln_pickle():
    raw = request.cookies.get("session", b"")
    obj = pickle.loads(raw)
    return obj


def vuln_yaml():
    raw = request.data
    return yaml.load(raw)
