"""Code injection trigger — VP-008 (CWE-95)."""
from flask import request


def vuln_eval():
    expr = request.args.get("expr", "1+1")
    result = eval(expr)
    return str(result)


def vuln_exec():
    code = request.args.get("code", "")
    exec(code)
