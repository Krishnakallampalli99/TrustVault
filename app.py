import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "private_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("TRUSTVAULT_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
DB_PATH = BASE_DIR / "trustvault.db"
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "xlsx", "csv", "ppt", "pptx"}

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('admin','owner','viewer')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'General',
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
            created_at TEXT NOT NULL,
            UNIQUE(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")

def log_event(actor_id, action, details):
    with db() as con:
        con.execute("INSERT INTO audit_logs(actor_id, action, details, created_at) VALUES(?,?,?,?)",
                    (actor_id, action, details[:500], now()))

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as con:
        return con.execute("SELECT id,name,email,role FROM users WHERE id=?", (uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in roles:
                flash("You are not authorized to perform that action.", "error")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapped
    return deco

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def can_read(doc, user):
    if not user:
        return False
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    with db() as con:
        grant = con.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                            (doc["id"], user["id"])).fetchone()
    return bool(grant)

def get_document(doc_id):
    with db() as con:
        return con.execute("""SELECT d.*, u.name AS owner_name, u.email AS owner_email
                              FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?""",
                           (doc_id,)).fetchone()

@app.context_processor
def inject_user():
    return {"me": current_user()}

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not name or not email or not password:
            flash("Please complete all required fields.", "error")
        elif len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            try:
                with db() as con:
                    con.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                                (name, email, generate_password_hash(password), "owner", now()))
                    uid = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
                log_event(uid, "ACCOUNT_CREATED", f"New account registered: {email}")
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
    return render_template("auth.html", mode="signup")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            log_event(user["id"], "LOGIN", f"Signed in: {email}")
            flash(f"Welcome back, {user['name'].split()[0]}.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user()
    log_event(user["id"], "LOGOUT", f"Signed out: {user['email']}")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with db() as con:
        if user["role"] == "admin":
            doc_count = con.execute("SELECT COUNT(*) n FROM documents").fetchone()["n"]
            user_count = con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            share_count = con.execute("SELECT COUNT(*) n FROM grants").fetchone()["n"]
            docs = con.execute("""SELECT d.*,u.name owner_name FROM documents d JOIN users u ON u.id=d.owner_id
                                  ORDER BY d.created_at DESC LIMIT 5""").fetchall()
            logs = con.execute("""SELECT a.*,u.name actor_name FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
                                  ORDER BY a.id DESC LIMIT 6""").fetchall()
        else:
            doc_count = con.execute("SELECT COUNT(*) n FROM documents WHERE owner_id=?", (user["id"],)).fetchone()["n"]
            user_count = None
            share_count = con.execute("SELECT COUNT(*) n FROM grants g JOIN documents d ON d.id=g.document_id WHERE d.owner_id=?",
                                      (user["id"],)).fetchone()["n"]
            docs = con.execute("""SELECT d.*,u.name owner_name FROM documents d JOIN users u ON u.id=d.owner_id
                                  WHERE d.owner_id=? OR d.id IN (SELECT document_id FROM grants WHERE user_id=?)
                                  ORDER BY d.created_at DESC LIMIT 5""", (user["id"], user["id"])).fetchall()
            logs = []
    return render_template("dashboard.html", doc_count=doc_count, user_count=user_count,
                           share_count=share_count, docs=docs, logs=logs)

@app.route("/documents")
@login_required
def documents():
    user = current_user()
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    with db() as con:
        if user["role"] == "admin":
            sql = """SELECT DISTINCT d.*,u.name owner_name FROM documents d JOIN users u ON u.id=d.owner_id
                     LEFT JOIN grants g ON g.document_id=d.id WHERE 1=1"""
            args = []
        else:
            sql = """SELECT DISTINCT d.*,u.name owner_name FROM documents d JOIN users u ON u.id=d.owner_id
                     LEFT JOIN grants g ON g.document_id=d.id WHERE (d.owner_id=? OR g.user_id=?)"""
            args = [user["id"], user["id"]]
        if q:
            sql += " AND (d.title LIKE ? OR d.original_name LIKE ? OR u.name LIKE ?)"
            args.extend([f"%{q}%"]*3)
        if category:
            sql += " AND d.category=?"
            args.append(category)
        sql += " ORDER BY d.created_at DESC"
        docs = con.execute(sql, args).fetchall()
        categories = con.execute("SELECT DISTINCT category FROM documents ORDER BY category").fetchall()
    return render_template("documents.html", docs=docs, categories=categories, q=q, category=category)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "General").strip() or "General"
        description = request.form.get("description", "").strip()
        user = current_user()
        if not file or not file.filename:
            flash("Choose a document to upload.", "error")
        elif not allowed_file(file.filename):
            flash("That file type is not allowed.", "error")
        elif not title:
            flash("Please enter a document title.", "error")
        else:
            original = secure_filename(file.filename)
            stored = secrets.token_hex(16) + "_" + original
            file.save(UPLOAD_DIR / stored)
            with db() as con:
                con.execute("""INSERT INTO documents(owner_id,title,stored_name,original_name,category,description,created_at)
                               VALUES(?,?,?,?,?,?,?)""",
                            (user["id"], title, stored, original, category, description, now()))
                doc_id = con.execute("SELECT id FROM documents WHERE stored_name=?", (stored,)).fetchone()["id"]
            log_event(user["id"], "DOCUMENT_UPLOADED", f"Uploaded document #{doc_id}: {title}")
            flash("Document uploaded securely.", "success")
            return redirect(url_for("documents"))
    return render_template("upload.html")

@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    user = current_user()
    doc = get_document(doc_id)
    if not doc or not can_read(doc, user):
        if user:
            log_event(user["id"], "ACCESS_DENIED", f"Denied download for document #{doc_id}")
        abort(404)
    log_event(user["id"], "DOCUMENT_DOWNLOADED", f"Downloaded document #{doc_id}: {doc['title']}")
    return send_from_directory(app.config["UPLOAD_FOLDER"], doc["stored_name"],
                               as_attachment=True, download_name=doc["original_name"])

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    user = current_user()
    doc = get_document(doc_id)
    if not doc or (user["role"] != "admin" and doc["owner_id"] != user["id"]):
        log_event(user["id"], "ACCESS_DENIED", f"Denied deletion for document #{doc_id}")
        abort(403)
    with db() as con:
        con.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    try:
        (UPLOAD_DIR / doc["stored_name"]).unlink(missing_ok=True)
    except OSError:
        pass
    log_event(user["id"], "DOCUMENT_DELETED", f"Deleted document #{doc_id}: {doc['title']}")
    flash("Document deleted.", "success")
    return redirect(url_for("documents"))

@app.route("/documents/<int:doc_id>/share", methods=["GET", "POST"])
@login_required
def share_document(doc_id):
    user = current_user()
    doc = get_document(doc_id)
    if not doc:
        abort(404)
    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        log_event(user["id"], "ACCESS_DENIED", f"Denied share management for document #{doc_id}")
        abort(403)
    if request.method == "POST":
        action = request.form.get("action")
        email = request.form.get("email", "").strip().lower()
        with db() as con:
            target = con.execute("SELECT id,role FROM users WHERE email=?", (email,)).fetchone()
            if action == "grant":
                permission = request.form.get("permission", "read")
                if not target:
                    flash("No registered user has that email.", "error")
                elif target["id"] == doc["owner_id"]:
                    flash("The owner already has access.", "warning")
                elif permission not in ("read", "edit"):
                    flash("Invalid permission selected.", "error")
                else:
                    con.execute("""INSERT INTO grants(document_id,user_id,permission,created_at) VALUES(?,?,?,?)
                                   ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission, created_at=excluded.created_at""",
                                (doc_id, target["id"], permission, now()))
                    log_event(user["id"], "ACCESS_GRANTED", f"{permission} access to document #{doc_id} granted to {email}")
                    flash("Access granted.", "success")
            elif action == "revoke":
                if target:
                    con.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc_id, target["id"]))
                log_event(user["id"], "ACCESS_REVOKED", f"Access to document #{doc_id} revoked for {email}")
                flash("Access revoked if a matching grant existed.", "success")
        return redirect(url_for("share_document", doc_id=doc_id))
    with db() as con:
        grants = con.execute("""SELECT g.permission,g.created_at,u.name,u.email FROM grants g JOIN users u ON u.id=g.user_id
                                WHERE g.document_id=? ORDER BY u.name""", (doc_id,)).fetchall()
    return render_template("share.html", doc=doc, grants=grants)

@app.route("/activity")
@roles_required("admin")
def activity():
    with db() as con:
        logs = con.execute("""SELECT a.*,u.name actor_name,u.email actor_email FROM audit_logs a
                              LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 250""").fetchall()
    return render_template("activity.html", logs=logs)

@app.route("/users")
@roles_required("admin")
def users():
    with db() as con:
        all_users = con.execute("SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC").fetchall()
    return render_template("users.html", users=all_users)

@app.route("/users/<int:user_id>/role", methods=["POST"])
@roles_required("admin")
def change_role(user_id):
    me = current_user()
    role = request.form.get("role")
    if role not in ("admin", "owner", "viewer"):
        flash("Invalid role.", "error")
    elif user_id == me["id"] and role != "admin":
        flash("You cannot remove your own admin role here.", "error")
    else:
        with db() as con:
            con.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        log_event(me["id"], "ROLE_CHANGED", f"Changed user #{user_id} role to {role}")
        flash("User role updated.", "success")
    return redirect(url_for("users"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        old = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        with db() as con:
            row = con.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
            if name:
                con.execute("UPDATE users SET name=? WHERE id=?", (name, user["id"]))
            if new:
                if not check_password_hash(row["password_hash"], old):
                    flash("Current password is incorrect.", "error")
                    return redirect(url_for("profile"))
                if len(new) < 8:
                    flash("New password must contain at least 8 characters.", "error")
                    return redirect(url_for("profile"))
                con.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), user["id"]))
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to perform this action."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested item could not be found."), 404

@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum upload size is 16 MB.", "error")
    return redirect(url_for("upload"))

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
