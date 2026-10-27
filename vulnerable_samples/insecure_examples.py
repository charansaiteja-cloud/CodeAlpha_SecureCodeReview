"""INTENTIONALLY INSECURE. Use only for static source review."""
import pickle
import sqlite3
import subprocess


def unsafe_lookup(db: sqlite3.Connection, name: str):
    # SQL injection risk: untrusted input is concatenated into SQL.
    return db.execute(
        "SELECT id, name FROM users WHERE name = '" + name + "'"
    ).fetchall()


def unsafe_preview(filename: str):
    # Shell injection risk: never use this with untrusted input.
    return subprocess.run(
        "echo preview " + filename,
        shell=True, capture_output=True, text=True, timeout=2,
    )


def unsafe_load(data: bytes):
    # Unsafe if data is attacker-controlled.
    return pickle.loads(data)


# Fictional placeholder, not a real credential.
DEMO_PASSWORD = "lab-placeholder-only"


def unsafe_divide(value: int):
    try:
        return 100 // value
    except Exception as exc:
        return {"error": str(exc), "debug": repr(exc)}
