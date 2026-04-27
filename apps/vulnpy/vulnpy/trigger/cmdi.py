"""Command injection trigger module — VP-001 (CWE-78)."""
import os
import subprocess
from flask import request


def vuln_os_system():
    cmd = request.args.get("cmd", "ls")
    os.system("echo " + cmd)


def vuln_subprocess_shell():
    target = request.args.get("host", "localhost")
    subprocess.call("ping -c 1 " + target, shell=True)


def vuln_popen():
    arg = request.args.get("arg", "")
    subprocess.Popen("grep " + arg + " /etc/passwd", shell=True)
