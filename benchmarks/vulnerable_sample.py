"""
Intentionally vulnerable sample file for SAST benchmark testing.
Contains known patterns (SQL injection, hardcoded secret, unsafe eval).
"""
import sqlite3
import os

# Vulnerability 1: Hardcoded credential (generic mock pattern)
HARDCODED_SECRET_KEY = "insecure_admin_password_12345"

def unsafe_query(username: str):
    conn = sqlite3.connect("app.db")
    # Vulnerability 2: SQL Injection via string formatting
    query = f"SELECT * FROM users WHERE name = '{username}'"
    conn.execute(query)

def unsafe_evaluation(user_input: str):
    # Vulnerability 3: Unsafe eval / code execution
    return eval(user_input)
