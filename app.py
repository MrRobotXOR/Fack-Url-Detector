from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from urllib.parse import urlparse
import joblib
import os
import re
import socket
import requests

app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ================= LOAD MODEL =================
try:
    model = joblib.load("model.pkl")
except:
    model = None

# ================= DATABASE =================

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    joined = db.Column(db.DateTime, default=datetime.utcnow)


class URLHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    result = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    explanation = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ================= FEATURE EXTRACTION =================

def extract_features(url):

    parsed = urlparse(url)

    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        1 if parsed.scheme == "https" else 0,
        1 if re.search(r"\d", parsed.netloc) else 0,
        len(parsed.netloc.split('.')),
        1 if parsed.netloc.replace('.', '').isdigit() else 0,
        1 if "//" in url[8:] else 0
    ]


# ================= IP GEOLOCATION =================

def get_ip_info(url):

    try:

        parsed = urlparse(url)
        domain = parsed.netloc

        # remove suspicious characters
        domain = domain.split("@")[-1]
        domain = domain.split(":")[0]

        if domain == "":
            return {
                "ip": "Unknown",
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown"
            }

        # get IP
        ip = socket.gethostbyname(domain)

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        data = response.json()

        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }

    except socket.gaierror:

        # Domain does not exist (fake URL case)
        return {
            "ip": "Not Found",
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Domain does not exist"
        }

    except Exception as e:

        print("IP ERROR:", e)

        return {
            "ip": "Error",
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }


# ================= EXPLANATION =================

def generate_explanation(url, result, confidence):

    message = f"AI Analysis Result\n\nURL: {url}\n\n"

    if result == "Fake":
        message += "⚠️ This URL looks suspicious.\nPossible phishing indicators detected.\n"
    else:
        message += "✅ This URL appears safe.\n"

    message += f"\nConfidence Level: {confidence}%"

    return message


# ================= ROUTES =================

@app.route("/")
def home():
    return redirect(url_for("login"))


# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already registered")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration Successful")
        return redirect(url_for("login"))

    return render_template("register.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid Credentials")

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():

    result = None
    confidence = None
    explanation = None
    ip_info = None

    if request.method == "POST":

        url = request.form["url"]

        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            flash("Invalid URL")
            return redirect(url_for("dashboard"))

        features = extract_features(url)

        if model:

            prediction = model.predict([features])
            probability = model.predict_proba([features])[0]

            confidence = round(max(probability) * 100, 2)

        else:

            prediction = [0]
            confidence = 50

        suspicious = False

        if "@" in url or url.count('.') > 4 or re.search(r"\d{3,}", url):
            suspicious = True

        if prediction[0] == 1 or suspicious:
            result = "Fake"
        else:
            result = "Safe"

        explanation = generate_explanation(url, result, confidence)

        ip_info = get_ip_info(url)

        new_scan = URLHistory(
            url=url,
            result=result,
            confidence=confidence,
            explanation=explanation,
            user_id=current_user.id
        )

        db.session.add(new_scan)
        db.session.commit()

    history = URLHistory.query.filter_by(user_id=current_user.id)\
        .order_by(URLHistory.date.desc()).limit(5)

    total = URLHistory.query.filter_by(user_id=current_user.id).count()

    fake = URLHistory.query.filter_by(
        user_id=current_user.id,
        result="Fake"
    ).count()

    safe = URLHistory.query.filter_by(
        user_id=current_user.id,
        result="Safe"
    ).count()

    return render_template(
        "dashboard.html",
        result=result,
        confidence=confidence,
        explanation=explanation,
        history=history,
        ip_info=ip_info,
        total=total,
        fake=fake,
        safe=safe
    )


# PROFILE
@app.route("/profile")
@login_required
def profile():

    total = URLHistory.query.filter_by(user_id=current_user.id).count()

    fake = URLHistory.query.filter_by(
        user_id=current_user.id,
        result="Fake"
    ).count()

    safe = URLHistory.query.filter_by(
        user_id=current_user.id,
        result="Safe"
    ).count()

    return render_template(
        "profile.html",
        total=total,
        fake=fake,
        safe=safe
    )


# LOGOUT
@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# ================= MAIN =================

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()