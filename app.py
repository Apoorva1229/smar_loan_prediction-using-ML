
import os
import re
import sqlite3
import joblib
import pandas as pd

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps


# ==========================================
# 1. FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "loanwise-local-development-secret"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(
    BASE_DIR,
    "instance",
    "loan_app.db"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model.pkl"
)

os.makedirs(
    os.path.dirname(DATABASE),
    exist_ok=True
)


# ==========================================
# 2. LOAD MACHINE LEARNING MODEL
# ==========================================

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        "model.pkl not found in project folder."
    )

model = joblib.load(MODEL_PATH)

FEATURES = [
    "Gender",
    "Marital_Status",
    "Applicant_Income",
    "Loan_Amount",
    "Credit_Score"
]


# ==========================================
# 3. DATABASE CONNECTION
# ==========================================

def get_db():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# ==========================================
# 4. CREATE DATABASE TABLES
# ==========================================


def create_tables():
    conn = get_db()

    try:
        # Create users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create predictions table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                applicant_income REAL NOT NULL,
                loan_amount REAL NOT NULL,
                credit_score TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # Check users table columns
        user_columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        ]

        # Add missing created_at column
        if "created_at" not in user_columns:
            conn.execute("""
                ALTER TABLE users
                ADD COLUMN created_at TIMESTAMP
            """)

            conn.execute("""
                UPDATE users
                SET created_at = CURRENT_TIMESTAMP
                WHERE created_at IS NULL
            """)

        # Check predictions table columns
        prediction_columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(predictions)"
            ).fetchall()
        ]

        if "created_at" not in prediction_columns:
            conn.execute("""
                ALTER TABLE predictions
                ADD COLUMN created_at TIMESTAMP
            """)

            conn.execute("""
                UPDATE predictions
                SET created_at = CURRENT_TIMESTAMP
                WHERE created_at IS NULL
            """)

        conn.commit()

    finally:
        conn.close()



# ==========================================
# 5. LOGIN REQUIRED
# ==========================================

def login_required(func):

    @wraps(func)

    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


# ==========================================
# 6. HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template("home.html")


# ==========================================
# 7. REGISTRATION PAGE
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:

        return redirect(url_for("dashboard"))

    if request.method == "POST":

        name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # Check empty fields

        if not name or not email or not password or not confirm_password:

            flash(
                "Please fill all fields.",
                "danger"
            )

            return redirect(url_for("register"))

        # Validate name

        if len(name) > 100:

            flash(
                "Name must be under 100 characters.",
                "danger"
            )

            return redirect(url_for("register"))

        # Validate email

        email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

        if not re.match(email_pattern, email):

            flash(
                "Enter a valid email address.",
                "danger"
            )

            return redirect(url_for("register"))

        # Validate password

        if len(password) < 8:

            flash(
                "Password must have at least 8 characters.",
                "danger"
            )

            return redirect(url_for("register"))

        # Confirm password

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(url_for("register"))

        # Hash password

        hashed_password = generate_password_hash(password)

        conn = get_db()

        try:

            conn.execute("""
                INSERT INTO users
                (name, email, password)

                VALUES (?, ?, ?)

            """, (
                name,
                email,
                hashed_password
            ))

            conn.commit()

            user = conn.execute("""
                SELECT id, name
                FROM users
                WHERE email = ?

            """, (email,)).fetchone()

            # Create login session

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            flash(
                "Registration successful! Welcome to LoanWise.",
                "success"
            )

            # Redirect to dashboard

            return redirect(
                url_for("dashboard")
            )

        except sqlite3.IntegrityError:

            flash(
                "Email already registered. Please login.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        except sqlite3.Error:

            conn.rollback()

            app.logger.exception(
                "Registration database error"
            )

            flash(
                "Registration failed. Please try again.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        finally:

            conn.close()

    return render_template("register.html")


# ==========================================
# 8. LOGIN PAGE
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:

        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE email = ?

        """, (email,)).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            flash(
                "Login successful!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password.",
            "danger"
        )

    return render_template("login.html")


# ==========================================
# 9. DASHBOARD
# ==========================================


@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    user_id = session["user_id"]

    # Total predictions
    total = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE user_id = ?
    """, (user_id,)).fetchone()[0]

    # Approved predictions
    approved = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE user_id = ?
        AND result = 'Approved'
    """, (user_id,)).fetchone()[0]

    # Rejected predictions
    rejected = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE user_id = ?
        AND result = 'Rejected'
    """, (user_id,)).fetchone()[0]

    # Recent prediction records
    recent = conn.execute("""
        SELECT *
        FROM predictions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    """, (user_id,)).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        approved=approved,
        rejected=rejected,
        recent=recent
    )



# ==========================================
# 10. MACHINE LEARNING PREDICTION
# ==========================================

@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict():

    if request.method == "POST":

        try:

            gender = request.form.get(
                "gender",
                request.form.get("Gender", "")
            )

            marital = request.form.get(
                "marital_status",
                request.form.get("Marital_Status", "")
            )

            income = float(
                request.form.get(
                    "applicant_income",
                    request.form.get("Applicant_Income", "")
                )
            )

            amount = float(
                request.form.get(
                    "loan_amount",
                    request.form.get("Loan_Amount", "")
                )
            )

            credit = request.form.get(
                "credit_score",
                request.form.get("Credit_Score", "")
            )

            # Validate inputs

            if gender not in ["Male", "Female"]:

                raise ValueError("Invalid gender.")

            if marital not in ["Single", "Married"]:

                raise ValueError("Invalid marital status.")

            if credit not in ["Poor", "Not Bad", "Good"]:

                raise ValueError("Invalid credit score.")

            if income <= 0 or amount <= 0:

                raise ValueError("Invalid income or loan amount.")

            # Convert input values

            gender_val = 1 if gender == "Male" else 0

            marital_val = 1 if marital == "Married" else 0

            credit_val = 0 if credit == "Poor" else 1

            # Create model input

            input_data = pd.DataFrame([{

                "Gender": gender_val,

                "Marital_Status": marital_val,

                "Applicant_Income": income,

                "Loan_Amount": amount,

                "Credit_Score": credit_val

            }], columns=FEATURES)

            # MACHINE LEARNING MODEL PREDICTION

            prediction = model.predict(input_data)

            result = (
                "Approved"
                if int(prediction[0]) == 1
                else "Rejected"
            )

            # Save prediction in database

            conn = get_db()

            conn.execute("""

                INSERT INTO predictions

                (
                    user_id,
                    applicant_income,
                    loan_amount,
                    credit_score,
                    result
                )

                VALUES (?, ?, ?, ?, ?)

            """, (

                session["user_id"],

                income,

                amount,

                credit,

                result

            ))

            conn.commit()

            conn.close()

            return render_template(
                "predict.html",
                result=result
            )

        except (ValueError, TypeError):

            flash(
                "Please enter valid applicant details.",
                "danger"
            )

        except Exception:

            app.logger.exception(
                "Prediction failed"
            )

            flash(
                "Prediction failed. Check your model and inputs.",
                "danger"
            )

    return render_template("predict.html")


# ==========================================
# 11. PREDICTION HISTORY
# ==========================================

@app.route("/history")
@login_required
def history():

    conn = get_db()

    records = conn.execute("""

        SELECT *
        FROM predictions
        WHERE user_id = ?
        ORDER BY created_at DESC

    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    return render_template(
        "history.html",
        records=records,
        history=records
    )


# ==========================================
# 12. USER PROFILE
# ==========================================

@app.route("/profile")
@login_required
def profile():

    conn = get_db()

    user = conn.execute("""

        SELECT id, name, email, created_at
        FROM users
        WHERE id = ?

    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    return render_template(
        "profile.html",
        user=user
    )


# ==========================================
# 13. LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have logged out successfully.",
        "success"
    )

    return redirect(url_for("home"))


# ==========================================
# 14. ERROR HANDLING
# ==========================================

@app.errorhandler(404)
def page_not_found(error):

    return "Page not found (404)", 404


@app.errorhandler(500)
def internal_server_error(error):

    return "Internal server error (500)", 500


# ==========================================
# 15. RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
