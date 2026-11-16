
import os
import sqlite3
import secrets
import hashlib

from datetime import datetime, timedelta
from functools import wraps

import joblib
import pandas as pd

from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from flask_mail import Mail, Message

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# LOAD ENVIRONMENT VARIABLES
load_dotenv()


# PROJECT PATHS
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB_DIR = os.path.join(BASE_DIR, "instance")
DATABASE = os.path.join(DB_DIR, "loan_app.db")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

os.makedirs(DB_DIR, exist_ok=True)


# FLASK APPLICATION
app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Please set SECRET_KEY in your .env file.")


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_USE_TLS=True,

    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),

    MAIL_DEFAULT_SENDER=os.getenv("MAIL_USERNAME")
)


mail = Mail(app)


# LOAD MACHINE LEARNING MODEL
model = None

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)


FEATURES = [
    "Gender",
    "Marital_Status",
    "Applicant_Income",
    "Loan_Amount",
    "Credit_Score"
]


# DATABASE CONNECTION
def get_db():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# CREATE DATABASE TABLES
def create_tables():

    conn = get_db()

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );


    CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        gender TEXT,
        marital_status TEXT,
        applicant_income REAL,
        loan_amount REAL,
        credit_score TEXT,
        result TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );


    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );


    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    """)


    # ADD MISSING PREDICTION COLUMNS
    columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(predictions)"
        ).fetchall()
    }

    additions = {
        "gender": "TEXT",
        "marital_status": "TEXT",
        "applicant_income": "REAL",
        "loan_amount": "REAL",
        "credit_score": "TEXT"
    }

    for name, definition in additions.items():

        if name not in columns:

            conn.execute(
                f"ALTER TABLE predictions ADD COLUMN {name} {definition}"
            )

    conn.commit()

    conn.close()


create_tables()


# USER LOGIN DECORATOR
def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash("Please login first.", "warning")

            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# ADMIN LOGIN DECORATOR
def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "admin_id" not in session:

            flash("Admin login required.", "warning")

            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return wrapper


# HOME PAGE
@app.route("/")
def home():

    return render_template("index.html")


# USER REGISTRATION
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:

            flash(
                "Enter all details. Password must be at least 8 characters.",
                "danger"
            )

            return render_template("register.html")

        conn = get_db()

        try:

            hashed_password = generate_password_hash(password)

            conn.execute("""

                INSERT INTO users(name, email, password)

                VALUES (?, ?, ?)

            """, (name, email, hashed_password))

            conn.commit()

            flash(
                "Registration successful. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash("Email already registered.", "danger")

        finally:

            conn.close()

    return render_template("register.html")


# USER LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"], password
        ):

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


# USER LOGOUT
@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("home"))


# USER DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    uid = session["user_id"]

    total = conn.execute("""

        SELECT COUNT(*)

        FROM predictions

        WHERE user_id=?

    """, (uid,)).fetchone()[0]

    recent = conn.execute("""

        SELECT *

        FROM predictions

        WHERE user_id=?

        ORDER BY id DESC

        LIMIT 5

    """, (uid,)).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        recent=recent
    )


# LOAN PREDICTION
@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict():

    gender = ""
    marital_status = ""
    applicant_income = ""
    loan_amount = ""
    credit_score = ""

    result = None

    if request.method == "POST":

        # GET FORM VALUES
        gender = request.form.get("gender", "")

        marital_status = request.form.get(
            "marital_status", ""
        )

        applicant_income = request.form.get(
            "applicant_income", ""
        )

        loan_amount = request.form.get(
            "loan_amount", ""
        )

        credit_score = request.form.get(
            "credit_score", ""
        )


        # CHECK MODEL
        if model is None:

            flash(
                "model.pkl is missing. Copy your trained model into the project folder.",
                "danger"
            )

        else:

            # VALIDATE FORM DETAILS
            try:

                income = float(applicant_income)

                amount = float(loan_amount)

                if (
                    gender not in ("Male", "Female")
                    or marital_status not in ("Married", "Single")
                    or credit_score not in ("Good", "Not Bad", "Poor")
                    or income < 0
                    or amount < 0
                ):

                    raise ValueError("Invalid application details")


                # PREPARE MODEL INPUT
                row = pd.DataFrame([{

                    "Gender": 1 if gender == "Male" else 0,

                    "Marital_Status": (
                        1 if marital_status == "Married" else 0
                    ),

                    "Applicant_Income": income,

                    "Loan_Amount": amount,

                    "Credit_Score": (
                        0 if credit_score == "Poor" else 1
                    )

                }], columns=FEATURES)


                # PREDICT RESULT
                prediction = int(model.predict(row)[0])

                result = (
                    "Approved"
                    if prediction == 1
                    else "Rejected"
                )


                # SAVE PREDICTION IN DATABASE
                conn = get_db()

                try:

                    conn.execute("""

                        INSERT INTO predictions
                        (
                            user_id,
                            gender,
                            marital_status,
                            applicant_income,
                            loan_amount,
                            credit_score,
                            result
                        )

                        VALUES (?, ?, ?, ?, ?, ?, ?)

                    """, (

                        session["user_id"],
                        gender,
                        marital_status,
                        income,
                        amount,
                        credit_score,
                        result

                    ))

                    conn.commit()

                finally:

                    conn.close()


            except (ValueError, TypeError):

                result = None

                flash(
                    "Please enter valid application details.",
                    "danger"
                )


            except Exception:

                result = None

                app.logger.exception("Prediction failed")

                flash(
                    "Prediction failed. Please check your model and database.",
                    "danger"
                )


    # DISPLAY RESULT AND RETAIN FORM VALUES
    return render_template(

        "predict.html",

        gender=gender,

        marital_status=marital_status,

        applicant_income=applicant_income,

        loan_amount=loan_amount,

        credit_score=credit_score,

        result=result

    )


# USER PREDICTION HISTORY
@app.route("/history")
@login_required
def history():

    conn = get_db()

    rows = conn.execute("""

        SELECT *

        FROM predictions

        WHERE user_id=?

        ORDER BY id DESC

    """, (session["user_id"],)).fetchall()

    conn.close()

    return render_template(
        "history.html",
        rows=rows
    )


# USER PROFILE
@app.route("/profile")
@login_required
def profile():

    conn = get_db()

    user = conn.execute("""

        SELECT id, name, email, created_at

        FROM users

        WHERE id=?

    """, (session["user_id"],)).fetchone()

    conn.close()

    return render_template(
        "profile.html",
        user=user
    )


# FORGOT PASSWORD
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        conn = get_db()

        user = conn.execute(

            "SELECT * FROM users WHERE email=?",

            (email,)

        ).fetchone()

        if user:

            token = secrets.token_urlsafe(32)

            token_hash = hashlib.sha256(
                token.encode()
            ).hexdigest()

            expires = (
                datetime.utcnow() + timedelta(minutes=30)
            ).isoformat()

            conn.execute("""

                INSERT INTO password_reset_tokens

                (user_id, token_hash, expires_at)

                VALUES (?, ?, ?)

            """, (user["id"], token_hash, expires))

            conn.commit()

            reset_url = url_for(

                "reset_password",

                token=token,

                _external=True

            )

            try:

                if (
                    not app.config["MAIL_USERNAME"]
                    or not app.config["MAIL_PASSWORD"]
                ):

                    raise RuntimeError(
                        "Email settings are missing."
                    )

                message = Message(

                    "LoanWise Password Reset",

                    recipients=[email],

                    body=(

                        "Use this link within 30 minutes "
                        "to reset your password:\n"

                        + reset_url

                    )

                )

                mail.send(message)

            except Exception:

                app.logger.exception(
                    "Password reset email failed"
                )

                flash(
                    "Email could not be sent. Check your .env settings.",
                    "danger"
                )

                conn.close()

                return render_template(
                    "forgot_password.html"
                )

        conn.close()

        flash(
            "If the email is registered, a reset link will be sent.",
            "success"
        )

    return render_template("forgot_password.html")


# RESET PASSWORD
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    conn = get_db()

    record = conn.execute("""

        SELECT *

        FROM password_reset_tokens

        WHERE token_hash=? AND used=0

    """, (token_hash,)).fetchone()

    valid = False

    if record:

        try:

            valid = (

                datetime.fromisoformat(record["expires_at"])

                > datetime.utcnow()

            )

        except ValueError:

            valid = False

    if not valid:

        conn.close()

        flash(
            "Reset link is invalid or expired.",
            "danger"
        )

        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        password = request.form.get("password", "")

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )

        else:

            hashed_password = generate_password_hash(password)

            conn.execute("""

                UPDATE users

                SET password=?

                WHERE id=?

            """, (
                hashed_password,
                record["user_id"]
            ))

            conn.execute("""

                UPDATE password_reset_tokens

                SET used=1

                WHERE id=?

            """, (record["id"],))

            conn.commit()

            conn.close()

            flash(
                "Password updated successfully.",
                "success"
            )

            return redirect(url_for("login"))

    conn.close()

    return render_template("reset_password.html")


# ADMIN LOGIN
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        conn = get_db()

        admin = conn.execute(

            "SELECT * FROM admins WHERE username=?",

            (username,)

        ).fetchone()

        conn.close()

        if admin and check_password_hash(
            admin["password"], password
        ):

            session.clear()

            session["admin_id"] = admin["id"]

            session["admin_username"] = admin["username"]

            return redirect(url_for("admin_dashboard"))

        flash(
            "Invalid admin username or password.",
            "danger"
        )

    return render_template("admin_login.html")


# ADMIN LOGOUT
@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():

    session.pop("admin_id", None)

    session.pop("admin_username", None)

    flash(
        "Admin logged out.",
        "success"
    )

    return redirect(url_for("admin_login"))


# ADMIN DASHBOARD
@app.route("/admin")
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():

    conn = get_db()

    total_users = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    total_predictions = conn.execute(
        "SELECT COUNT(*) FROM predictions"
    ).fetchone()[0]

    approved = conn.execute("""

        SELECT COUNT(*)

        FROM predictions

        WHERE result='Approved'

    """).fetchone()[0]

    rejected = conn.execute("""

        SELECT COUNT(*)

        FROM predictions

        WHERE result='Rejected'

    """).fetchone()[0]

    recent = conn.execute("""

        SELECT p.*, u.name AS user_name, u.email

        FROM predictions p

        LEFT JOIN users u ON p.user_id=u.id

        ORDER BY p.id DESC

        LIMIT 8

    """).fetchall()

    new_users = conn.execute("""

        SELECT *

        FROM users

        ORDER BY id DESC

        LIMIT 6

    """).fetchall()

    conn.close()

    return render_template(

        "admin_dashboard.html",

        total_users=total_users,

        total_predictions=total_predictions,

        approved=approved,

        rejected=rejected,

        recent=recent,

        new_users=new_users

    )


# ADMIN: MANAGE USERS
@app.route("/admin/users")
@admin_required
def manage_users():

    conn = get_db()

    users = conn.execute("""

        SELECT

            u.id,

            u.name,

            u.email,

            u.created_at,

            COUNT(p.id) AS prediction_count

        FROM users u

        LEFT JOIN predictions p ON p.user_id=u.id

        GROUP BY u.id

        ORDER BY u.id DESC

    """).fetchall()

    conn.close()

    return render_template(
        "manage_users.html",
        users=users
    )


# ADMIN: VIEW LOAN APPLICATIONS
@app.route("/admin/predictions")
@admin_required
def admin_predictions():

    conn = get_db()

    rows = conn.execute("""

        SELECT p.*, u.name AS user_name, u.email

        FROM predictions p

        LEFT JOIN users u ON u.id=p.user_id

        ORDER BY p.id DESC

    """).fetchall()

    conn.close()

    return render_template(
        "loan_applications.html",
        rows=rows
    )


# ADMIN: REPORTS
@app.route("/admin/reports")
@admin_required
def reports():

    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM predictions"
    ).fetchone()[0]

    approved = conn.execute("""

        SELECT COUNT(*)

        FROM predictions

        WHERE result='Approved'

    """).fetchone()[0]

    rejected = conn.execute("""

        SELECT COUNT(*)

        FROM predictions

        WHERE result='Rejected'

    """).fetchone()[0]

    conn.close()

    approved_pct = (
        round(approved * 100 / total, 1)
        if total else 0
    )

    rejected_pct = (
        round(rejected * 100 / total, 1)
        if total else 0
    )

    return render_template(

        "reports.html",

        total=total,

        approved=approved,

        rejected=rejected,

        approved_pct=approved_pct,

        rejected_pct=rejected_pct

    )


# RUN APPLICATION
if __name__ == "__main__":

    app.run(
        debug=os.getenv(
            "FLASK_DEBUG", "false"
        ).lower() == "true"
    )
