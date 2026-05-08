# Before running, make sure to run in the terminal:
# pip install bcrypt
# pip install flask

from flask import Flask, request, redirect, url_for, render_template, session
from database import get_db, init_db
import bcrypt
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

init_db()

# ---------- PASSWORD VALIDATION ----------
def is_valid_password(password):
    return (
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[^A-Za-z0-9]", password)
    )

# ---------- ROUTES ----------
@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            error = "Incorrect username or password"

    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            error = "Fields cannot be empty"
        elif not is_valid_password(password):
            error = "Password must include uppercase, lowercase, number, and special character"
        else:
            conn = get_db()
            try:
                hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_pw)
                )
                conn.commit()

                return redirect(url_for("dashboard"))
            except:
                conn.rollback()
                error = "Username already exists or error occurred"
            finally:
                session["user"] = username
                conn.close()

    return render_template("register.html", error=error)

@app.route("/dashboard")
def dashboard():
    conn = get_db()
    if "user" not in session:
        return redirect(url_for("login"))
    entries = conn.execute(
        "SELECT * FROM entries WHERE user=?",
        (session["user"],)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", entries=entries, username=session["user"])


@app.route("/image/<int:id>")
def get_image(id):
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    entry = conn.execute(
        "SELECT image FROM entries WHERE id=? AND user=?",
        (id, session["user"])
    ).fetchone()
    conn.close()

    if entry and entry["image"]:
        return entry["image"], 200, {'Content-Type': 'image/jpeg'}
    else:
        return "Image not found", 404
@app.route("/create", methods=["GET", "POST"])
def create():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()
        file = request.files.get('image_file')
    
        image_data = None

        if file and file.filename:
            image_data = file.read()

        conn = get_db()
        conn.execute(
            "INSERT INTO entries (user, title, content, image) VALUES (?, ?, ?, ?)",
            (session["user"], title, content, image_data)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    return render_template("create.html")


# ---------- UPDATE ----------
@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    entry = conn.execute(
        "SELECT * FROM entries WHERE id=? AND user=?",
        (id, session["user"])
    ).fetchone()


    if not entry:
        return "Not allowed"

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()


        conn.execute(
            "UPDATE entries SET title=?, content=? WHERE id=? AND user=?",
            (title, content, id, session["user"])
        )
        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    return render_template("edit.html", entry=entry)


# ---------- DELETE ----------
@app.route("/delete/<int:id>")
def delete(id):
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    deleted = conn.execute(
        "DELETE FROM entries WHERE id=? AND user=?",
        (id, session["user"])
    ).rowcount

    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))



@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)