import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# -------------------------
# Config & helpers
# -------------------------

def make_db_uri() -> str:
    url = os.environ.get("DATABASE_URL")
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url or "sqlite:///local.db"

def make_secret_key() -> str:
    return os.environ.get("SECRET_KEY", "dev-secret-key")

def ts_serializer():
    return URLSafeTimedSerializer(make_secret_key())

def send_email(to_email: str, subject: str, body: str) -> None:
    """
    Send email via SMTP if MAIL_* env vars are set; otherwise print to console.
    Required env:
      MAIL_SERVER, MAIL_PORT (int), MAIL_USERNAME, MAIL_PASSWORD, MAIL_USE_TLS (true/false), MAIL_SENDER
    """
    server = os.environ.get("MAIL_SERVER")
    port = int(os.environ.get("MAIL_PORT", "0") or "0")
    username = os.environ.get("MAIL_USERNAME")
    password = os.environ.get("MAIL_PASSWORD")
    use_tls = os.environ.get("MAIL_USE_TLS", "true").lower() in ("1","true","yes")
    sender = os.environ.get("MAIL_SENDER", username or "no-reply@example.com")

    if not server or not port or not username or not password:
        print("\n--- EMAIL (simulation) ---")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(body)
        print("--- END EMAIL ---\n")
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email

    with smtplib.SMTP(server, port) as smtp:
        if use_tls:
            smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)

# -------------------------
# App / DB init
# -------------------------

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = make_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_size": int(os.environ.get("DB_POOL_SIZE", "5")),
    "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "5")),
}
app.secret_key = make_secret_key()

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------
# Models
# -------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")   # "admin" / "user"
    is_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    invoices = db.relationship("Invoice", backref="owner", lazy=True)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

    def get_id(self):
        return str(self.id)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    paid = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    @property
    def days_left(self):
        return (self.due_date - date.today()).days

# -------------------------
# Login manager
# -------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------
# Decorators
# -------------------------

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# -------------------------
# Auth routes
# -------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Podaj email i hasło.", "warning")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Taki email już istnieje.", "danger")
            return redirect(url_for("register"))
        user = User(email=email, role="user", is_confirmed=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # send confirmation
        token = ts_serializer().dumps({"uid": user.id, "action": "confirm"})
        confirm_link = url_for("confirm_email", token=token, _external=True)
        send_email(
            user.email,
            "Potwierdź konto",
            f"Cześć! Kliknij, aby potwierdzić konto: {confirm_link}\n\nLink ważny 48h."
        )
        flash("Konto utworzone. Sprawdź email i potwierdź konto.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        data = ts_serializer().loads(token, max_age=172800)  # 48h
        if data.get("action") != "confirm":
            raise BadSignature("Wrong action")
    except (BadSignature, SignatureExpired):
        flash("Link potwierdzający jest nieprawidłowy lub wygasł.", "danger")
        return redirect(url_for("login"))

    user = User.query.get_or_404(data["uid"])
    if not user.is_confirmed:
        user.is_confirmed = True
        db.session.commit()
        flash("Konto potwierdzone. Możesz się zalogować.", "success")
    else:
        flash("Konto było już potwierdzone.", "info")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Nieprawidłowy email lub hasło.", "danger")
            return redirect(url_for("login"))
        if not user.is_confirmed:
            flash("Potwierdź email zanim się zalogujesz.", "warning")
            return redirect(url_for("login"))
        login_user(user)
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Wylogowano pomyślnie.", "info")
    return redirect(url_for("login"))

# -------------------------
# Password reset
# -------------------------

@app.route("/reset", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Jeśli email istnieje, wysłaliśmy instrukcje resetu.", "info")
            return redirect(url_for("login"))
        token = ts_serializer().dumps({"uid": user.id, "action": "reset"})
        link = url_for("reset_token", token=token, _external=True)
        send_email(
            user.email,
            "Reset hasła",
            f"Kliknij, aby ustawić nowe hasło: {link}\n\nLink ważny 2 godziny."
        )
        flash("Wysłaliśmy link do resetu hasła (sprawdź pocztę).", "success")
        return redirect(url_for("login"))
    return render_template("reset_request.html")

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_token(token):
    try:
        data = ts_serializer().loads(token, max_age=7200)  # 2h
        if data.get("action") != "reset":
            raise BadSignature("Wrong action")
    except (BadSignature, SignatureExpired):
        flash("Link resetujący jest nieprawidłowy lub wygasł.", "danger")
        return redirect(url_for("reset_request"))

    user = User.query.get_or_404(data["uid"])
    if request.method == "POST":
        new_pass = request.form.get("password", "")
        if not new_pass or len(new_pass) < 6:
            flash("Hasło musi mieć co najmniej 6 znaków.", "warning")
            return redirect(url_for("reset_token", token=token))
        user.set_password(new_pass)
        db.session.commit()
        flash("Hasło zmienione. Zaloguj się nowym hasłem.", "success")
        return redirect(url_for("login"))
    return render_template("reset_form.html")

# -------------------------
# Invoices
# -------------------------

@app.route("/")
@login_required
def index():
    if current_user.role == "admin":
        invoices = Invoice.query.order_by(Invoice.due_date.asc()).all()
    else:
        invoices = Invoice.query.filter_by(user_id=current_user.id).order_by(Invoice.due_date.asc()).all()
    total = sum(i.amount for i in invoices if not i.paid)
    return render_template("index.html", invoices=invoices, today=date.today(), total_open=total)

@app.route("/add", methods=["POST"])
@login_required
def add_invoice():
    name = request.form.get("name", "").strip()
    amount = float(request.form.get("amount", "0") or 0)
    due_date_str = request.form.get("due_date", "")
    if not name or amount <= 0 or not due_date_str:
        flash("Uzupełnij poprawnie nazwę, kwotę i termin.", "warning")
        return redirect(url_for("index"))
    due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
    inv = Invoice(name=name, amount=amount, due_date=due_date, user_id=current_user.id)
    db.session.add(inv)
    db.session.commit()
    flash("Faktura dodana.", "success")
    return redirect(url_for("index"))

@app.route("/pay/<int:invoice_id>", methods=["POST", "GET"])
@login_required
def pay_invoice(invoice_id):
    inv = Invoice.query.get_or_404(invoice_id)
    if inv.user_id != current_user.id and current_user.role != "admin":
        abort(403)
    inv.paid = True
    db.session.commit()
    flash("Oznaczono jako zapłaconą.", "success")
    return redirect(url_for("index"))

# -------------------------
# Admin
# -------------------------

@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/make-admin/<int:user_id>", methods=["POST"])
@admin_required
def admin_make_admin(user_id):
    u = User.query.get_or_404(user_id)
    u.role = "admin"
    db.session.commit()
    flash(f"Nadano uprawnienia admina: {u.email}", "success")
    return redirect(url_for("admin_users"))

# -------------------------
# Health
# -------------------------
@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200

# -------------------------
# CLI helper
# -------------------------
@app.cli.command("create-admin")
def create_admin():
    """Create initial admin user with env ADMIN_EMAIL / ADMIN_PASSWORD."""
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not email or not password:
        print("Set ADMIN_EMAIL and ADMIN_PASSWORD env vars before running this command.")
        return
    existing = User.query.filter_by(email=email).first()
    if existing:
        print("Admin already exists.")
        return
    u = User(email=email, role="admin", is_confirmed=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    print(f"Admin created: {email}")

# -------------------------
# App entry (dev)
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
