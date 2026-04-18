"""SQLite persistence for registered users."""

import os
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def _conn():
    return sqlite3.connect(DB_NAME)


# Pre-registered user accounts (phone is entered at registration by the user)
REGISTERED_USERS = [
    {"email": "username@gmail.com",  "password": "Secure@123"},
    {"email": "username1@gmail.com", "password": "Secure@123"},
    {"email": "username2@gmail.com", "password": "Secure@123"},
    {"email": "username3@gmail.com", "password": "Secure@123"},
]


def init_db():
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def ensure_demo_user():
    """Seed pre-registered user accounts if they do not already exist."""
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        for user in REGISTERED_USERS:
            row = c.execute(
                "SELECT id FROM users WHERE email = ?", (user["email"].lower(),)
            ).fetchone()
            if row:
                continue
            ph = generate_password_hash(user["password"])
            c.execute(
                "INSERT INTO users (email, phone, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (user["email"].lower(), "", ph, now),
            )


def create_user(email: str, phone: str, password: str) -> tuple[bool, str]:
    email = email.strip().lower()
    phone = (phone or "").strip()
    if not email or "@" not in email:
        return False, "Valid email is required."
    if not phone:
        return False, "Phone number is required."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    ph = generate_password_hash(password)
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO users (email, phone, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, phone, ph, now),
            )
        return True, "Account created. You can sign in."
    except sqlite3.IntegrityError:
        return False, "That email is already registered."


def verify_login(email: str, password: str) -> dict | None:
    email = email.strip().lower()
    with _conn() as c:
        row = c.execute(
            "SELECT id, email, phone, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    if not row:
        return None
    uid, em, phone, ph = row
    if not check_password_hash(ph, password):
        return None
    return {"id": uid, "email": em, "phone": phone or ""}


def get_user_by_id(user_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT id, email, phone FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "phone": row[2] or ""}
