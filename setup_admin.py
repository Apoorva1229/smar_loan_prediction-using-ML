
import os
import sqlite3
import getpass

from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "instance")
DATABASE = os.path.join(DB_DIR, "loan_app.db")

os.makedirs(DB_DIR, exist_ok=True)

username = input("Enter admin username: ").strip()
email = input("Enter admin email: ").strip().lower()
password = getpass.getpass("Enter admin password: ")

if not username or not email or len(password) < 8:
    raise SystemExit(
        "Enter a username, email and password of at least 8 characters."
    )

conn = sqlite3.connect(DATABASE)

conn.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

try:
    conn.execute("""
        INSERT INTO admins(username, email, password)
        VALUES (?, ?, ?)
    """, (
        username,
        email,
        generate_password_hash(password)
    ))

    conn.commit()

    print("Admin account created successfully!")
    print("Open /admin/login to sign in.")

except sqlite3.IntegrityError:
    print("This admin username or email already exists.")

finally:
    conn.close()
