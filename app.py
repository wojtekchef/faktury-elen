from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, date

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://myuser:mypassword@db:5432/mydb"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "dev-secret-key"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    paid = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def days_left(self):
        return (self.due_date - date.today()).days

@app.route("/")
def index():
    invoices = Invoice.query.order_by(Invoice.due_date.asc()).all()
    return render_template("index.html", invoices=invoices, today=date.today())

@app.route("/add", methods=["POST"])
def add_invoice():
    name = request.form["name"]
    amount = float(request.form["amount"])
    due_date = datetime.strptime(request.form["due_date"], "%Y-%m-%d").date()
    invoice = Invoice(name=name, amount=amount, due_date=due_date)
    db.session.add(invoice)
    db.session.commit()
    return redirect(url_for("index"))

@app.route("/pay/<int:invoice_id>")
def pay_invoice(invoice_id):
    inv = Invoice.query.get_or_404(invoice_id)
    inv.paid = True
    db.session.commit()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
