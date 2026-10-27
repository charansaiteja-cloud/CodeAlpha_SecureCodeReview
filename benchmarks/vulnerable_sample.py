"""
Intentionally vulnerable sample file for SAST benchmark testing.
Contains patterns guaranteed to trigger Bandit (e.g., assert, eval).
"""
import sqlite3
import os

def unsafe_evaluation(user_input: str):
    # Triggers Bandit B307 (eval used)
    return eval(user_input)

def check_auth(is_admin: bool):
    # Triggers Bandit B101 (use of assert)
    assert is_admin, "User must be admin"
