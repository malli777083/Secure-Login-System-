from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = "users.db"


# Create database and users table
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Home page
@app.route("/")
def home():
    if "username" in session:
        return render_template("home.html", username=session["username"])

    return redirect("/login")


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input validation
        if not username or not password:
            flash("Username and password are required!")
            return redirect("/register")

        if len(username) < 3:
            flash("Username must contain at least 3 characters!")
            return redirect("/register")

        if len(password) < 6:
            flash("Password must contain at least 6 characters!")
            return redirect("/register")

        # Hash password
        hashed_password = generate_password_hash(
            password,
            method="pbkdf2:sha256"
        )

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Parameterized query prevents SQL injection
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration successful! Please login.")
            return redirect("/login")

        except sqlite3.IntegrityError:
            flash("Username already exists!")
            return redirect("/register")

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Parameterized query
        cursor.execute(
            "SELECT username, password FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):

            session["username"] = user[0]

            flash("Login successful!")
            return redirect("/")

        flash("Invalid username or password!")
        return redirect("/login")

    return render_template("login.html")


# Logout
@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
