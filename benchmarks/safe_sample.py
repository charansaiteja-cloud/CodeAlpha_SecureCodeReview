"""
Secure counterpart sample file for false-positive validation.
Uses parameterized queries, environment variables, and safe constructs.
"""
import sqlite3
import os

# Secure: Loaded from environment
SECRET_API_KEY = os.environ.get("API_KEY", "default-safe-key")

def safe_query(username: str):
    conn = sqlite3.connect("app.db")
    # Secure: Parameterized SQL query
    conn.execute("SELECT * FROM users WHERE name = ?", (username,))

def safe_operation(value: int):
    # Secure: Simple arithmetic, no eval
    return value * 2
