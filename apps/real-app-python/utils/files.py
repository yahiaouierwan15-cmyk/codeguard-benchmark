# utils/files.py - File handling utilities
# WARNING: This file intentionally contains security vulnerabilities for benchmark testing.

import os
import subprocess


UPLOAD_DIR = "/var/uploads/blog"


def get_file_content(filename: str) -> str:
    """Return the content of a file from the upload directory."""
    # CWE-22: Path Traversal — filename from user input joined without sanitization
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "r") as f:
        return f.read()


def convert_image(filename: str, target_format: str = "webp") -> str:
    """Convert an uploaded image to the target format using ImageMagick."""
    # CWE-78: Command Injection — filename from user input passed to shell with shell=True
    output_name = filename.rsplit(".", 1)[0] + "." + target_format
    output_path = os.path.join(UPLOAD_DIR, output_name)
    cmd = f"convert {UPLOAD_DIR}/{filename} {output_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Conversion failed: {result.stderr}")
    return output_path


def list_uploads() -> list:
    """List all files in the upload directory."""
    if not os.path.exists(UPLOAD_DIR):
        return []
    return os.listdir(UPLOAD_DIR)


def delete_file(filename: str) -> bool:
    """Delete a file from the upload directory."""
    filepath = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    return False
