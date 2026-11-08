import hashlib
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps

import requests

from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# قاعدة البيانات بجانب الملف (يعمل على أي جهاز بدون مسار ثابت)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example.db")

# ---------- إعدادات إرسال الإيميل (Brevo API) ----------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "").strip().strip('"').strip("'")
print("[DEBUG] key length:", len(BREVO_API_KEY), "| ends with:", BREVO_API_KEY[-6:])
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "hamoudaalshboul@gmail.com")   # يجب أن يكون موثقاً في Brevo
SENDER_NAME = os.environ.get("SENDER_NAME", "Accounting App")

OTP_TTL = 5 * 60        # صلاحية الرمز 5 دقائق
OTP_MAX_ATTEMPTS = 5    # أقصى محاولات خاطئة
RESEND_COOLDOWN = 60    # ثانية بين كل إرسال وآخر

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- قاعدة البيانات ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            age INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS otps (
            email TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_sent REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('income','expense')),
            title TEXT NOT NULL,
            amount REAL NOT NULL,
            created_at TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()


# ---------- OTP ----------
def hash_code(email, code):
    return hashlib.sha256(f"{email}:{code}:{app.secret_key}".encode()).hexdigest()


def send_otp_email(email, code):
    """يرسل الرمز إلى البريد الحقيقي عبر Brevo API. يرجع (نجاح, رسالة)."""
    if not BREVO_API_KEY or not SENDER_EMAIL:
        # وضع التطوير فقط: الطباعة في الطرفية
        print(f"[DEV] OTP for {email}: {code}")
        return False, "لم يتم ضبط BREVO_API_KEY / SENDER_EMAIL، تم طباعة الرمز في الطرفية فقط."

    html = f"""
    <div style="background:#05070d;padding:32px;font-family:Arial,sans-serif;color:#e8eefc">
      <div style="max-width:420px;margin:auto;background:#0b1020;border:1px solid #1d2a4d;
                  border-radius:16px;padding:32px;text-align:center">
        <h2 style="color:#4c8dff;margin:0 0 8px">رمز التحقق</h2>
        <p style="color:#8fa0c8;margin:0 0 24px">استخدم الرمز التالي لتسجيل الدخول</p>
        <div style="font-size:36px;letter-spacing:10px;font-weight:700;color:#fff;
                    background:#111a33;border-radius:12px;padding:16px">{code}</div>
        <p style="color:#8fa0c8;margin-top:24px;font-size:13px">صالح لمدة 5 دقائق. إذا لم تطلبه تجاهل الرسالة.</p>
      </div>
    </div>"""
    try:
        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "accept": "application/json",
                     "content-type": "application/json"},
            json={
                "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
                "to": [{"email": email}],
                "subject": "رمز التحقق الخاص بك",
                "htmlContent": html,
            },
            timeout=15,
        )
        if r.status_code in (200, 201):
            return True, "تم إرسال الرمز إلى بريدك."
        print("[Brevo error]", r.status_code, r.text)
        return False, "تعذر إرسال الرمز، تحقق من إعدادات الـ API."
    except requests.RequestException as e:
        print("[Brevo exception]", e)
        return False, "تعذر الاتصال بخدمة الإرسال."


def create_and_send_otp(email):
    code = f"{secrets.randbelow(1_000_000):06d}"
    now = time.time()
    conn = db()
    conn.execute(
        '''INSERT INTO otps (email, code_hash, expires_at, attempts, last_sent)
           VALUES (?,?,?,0,?)
           ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,
           expires_at=excluded.expires_at, attempts=0, last_sent=excluded.last_sent''',
        (email, hash_code(email, code), now + OTP_TTL, now))
    conn.commit()
    conn.close()
    return send_otp_email(email, code)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("email"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


# ---------- المصادقة ----------
@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("accounting" if session.get("email") else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("email"):
        return redirect(url_for("accounting"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not EMAIL_RE.match(email):
            flash("أدخل بريداً إلكترونياً صحيحاً.", "error")
            return render_template("login.html")

        conn = db()
        row = conn.execute("SELECT last_sent FROM otps WHERE email=?", (email,)).fetchone()
        conn.close()
        if row and time.time() - row["last_sent"] < RESEND_COOLDOWN:
            wait = int(RESEND_COOLDOWN - (time.time() - row["last_sent"]))
            flash(f"انتظر {wait} ثانية قبل طلب رمز جديد.", "error")
            return render_template("login.html")

        ok, msg = create_and_send_otp(email)
        session["pending_email"] = email
        flash(msg, "success" if ok else "error")
        return redirect(url_for("verify"))
    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        conn = db()
        row = conn.execute("SELECT * FROM otps WHERE email=?", (email,)).fetchone()

        if not row or time.time() > row["expires_at"]:
            conn.close()
            flash("انتهت صلاحية الرمز، اطلب رمزاً جديداً.", "error")
            return render_template("verify.html", email=email)

        if row["attempts"] >= OTP_MAX_ATTEMPTS:
            conn.close()
            flash("تجاوزت عدد المحاولات، اطلب رمزاً جديداً.", "error")
            return render_template("verify.html", email=email)

        if secrets.compare_digest(row["code_hash"], hash_code(email, code)):
            conn.execute("DELETE FROM otps WHERE email=?", (email,))
            conn.commit()
            conn.close()
            session.clear()
            session["email"] = email
            return redirect(url_for("accounting"))

        conn.execute("UPDATE otps SET attempts = attempts + 1 WHERE email=?", (email,))
        conn.commit()
        conn.close()
        flash("الرمز غير صحيح.", "error")
    return render_template("verify.html", email=email)


@app.route("/resend", methods=["POST"])
def resend():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("login"))
    conn = db()
    row = conn.execute("SELECT last_sent FROM otps WHERE email=?", (email,)).fetchone()
    conn.close()
    if row and time.time() - row["last_sent"] < RESEND_COOLDOWN:
        wait = int(RESEND_COOLDOWN - (time.time() - row["last_sent"]))
        flash(f"انتظر {wait} ثانية قبل إعادة الإرسال.", "error")
    else:
        ok, msg = create_and_send_otp(email)
        flash(msg, "success" if ok else "error")
    return redirect(url_for("verify"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- المحاسبة ----------
@app.route("/accounting")
@login_required
def accounting():
    conn = db()
    rows = conn.execute(
        "SELECT * FROM transactions WHERE email=? ORDER BY id DESC",
        (session["email"],)).fetchall()
    conn.close()
    income = sum(r["amount"] for r in rows if r["type"] == "income")
    expense = sum(r["amount"] for r in rows if r["type"] == "expense")
    return render_template("accounting.html", rows=rows, income=income,
                           expense=expense, balance=income - expense)


@app.route("/accounting/add", methods=["POST"])
@login_required
def add_transaction():
    t_type = request.form.get("type")
    title = request.form.get("title", "").strip()
    try:
        amount = float(request.form.get("amount", ""))
    except ValueError:
        amount = 0
    if t_type not in ("income", "expense") or not title or amount <= 0:
        flash("تحقق من بيانات العملية.", "error")
        return redirect(url_for("accounting"))
    conn = db()
    conn.execute(
        "INSERT INTO transactions (email, type, title, amount, created_at) VALUES (?,?,?,?,?)",
        (session["email"], t_type, title, amount,
         datetime.now().strftime("%Y-%m-%d %H:%M")))
    conn.commit()
    conn.close()
    return redirect(url_for("accounting"))


@app.route("/accounting/delete/<int:tid>", methods=["POST"])
@login_required
def delete_transaction(tid):
    conn = db()
    conn.execute("DELETE FROM transactions WHERE id=? AND email=?", (tid, session["email"]))
    conn.commit()
    conn.close()
    return redirect(url_for("accounting"))


# ---------- إدارة المستخدمين (CRUD الأصلي) ----------
@app.route("/users")
@login_required
def users_page():
    conn = db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template("index.html", users=users)


@app.route("/add_user", methods=["POST"])
@login_required
def add_user_route():
    conn = db()
    conn.execute("INSERT INTO users (name, age) VALUES (?,?)",
                 (request.form["name"], request.form["age"]))
    conn.commit()
    conn.close()
    return redirect(url_for("users_page"))


@app.route("/update_user/<int:id>", methods=["GET", "POST"])
@login_required
def update_user_route(id):
    conn = db()
    if request.method == "POST":
        conn.execute("UPDATE users SET name=?, age=? WHERE id=?",
                     (request.form["name"], request.form["age"], id))
        conn.commit()
        conn.close()
        return redirect(url_for("users_page"))
    user = conn.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()
    conn.close()
    if user is None:
        return redirect(url_for("users_page"))
    return render_template("update_user.html", user=user)


@app.route("/delete_user/<int:id>", methods=["POST"])
@login_required
def delete_user_route(id):
    conn = db()
    conn.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("users_page"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
