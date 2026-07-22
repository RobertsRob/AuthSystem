import os
import re
from flask import Flask, render_template, request, redirect, url_for, make_response, session
import requests
from dotenv import load_dotenv
import psycopg
import jwt
from datetime import datetime, timedelta, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_mail import Mail, Message
import secrets
import hashlib


load_dotenv()
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

oauth = OAuth(app)

try:
    google = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_AUTH_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_AUTH_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={ "scope": "openid email profile", "response_mode": "form_post", }
    )
except Exception as e:
    print(f"Failed to connect to google auth: {e}")

try:
    app.config.update(
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
    )
    mail = Mail(app)
except Exception as e:
    print(f"Failed to connect to flask mail: {e}")

def safe_render_template(template_file, jinja_info=None):
    try:
        if jinja_info:
            return render_template(template_file, **jinja_info)
        return render_template(template_file)
    except:
        return render_template("error.html")

def connect_to_database():
    conn, cur = (None, None)
    try:
        conn = psycopg.connect(
            dbname=os.getenv('POSTGRES_DB'),
            user=os.getenv('POSTGRES_USER'),
            password=os.getenv('POSTGRES_PASSWORD'),
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=5432
        )
        cur = conn.cursor()

        cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        google_id TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
    finally:
        if conn:
            conn.commit()
    return (conn, cur)

def close_database(conn, cur):
    if cur:
        cur.close()
    if conn:
        conn.close()

def verify_token(token):
    data = {
        "secret": f"{os.getenv('HCAPTCHA')}",
        "response": token,
        "sitekey": "0ff041fe-1418-4c74-8bca-10882266eb3a",
    }
    j = requests.post(
        "https://api.hcaptcha.com/siteverify",
        data=data,
        timeout=5,
    ).json()
    return (True, []) if j.get("success") else (
        False,
        j.get("error-codes", []),
    )

def alreay_logged_in():
    jwtoken = request.cookies.get("access_token")
    try:
        jwt.decode(jwtoken, os.getenv('JWTSECRET'), algorithms=["HS256"])
        return True
    except jwt.InvalidTokenError:
        pass
    return False



@app.route("/")
def home():
    return safe_render_template("home_page.html")

@app.route("/login")
def login():
    if alreay_logged_in():
        return redirect(url_for("home_user"))
    
    error = request.args.get("error")
    return safe_render_template("login.html", {"error" : error})

@app.route("/signup")
def signup():
    if alreay_logged_in():
        return redirect(url_for("home_user"))

    error = request.args.get("error")
    return safe_render_template("signup.html", {"error" : error})

@app.route("/login_submit", methods=["POST"])
def login_submit():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return redirect(url_for('login', error="Please complete CAPTCHA"))
    
    if not verify_token(captcha_token):
        return redirect(url_for('login', error="CAPTCHA failed"))
    
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    if not username or not password:
        return redirect(url_for('login', error="Missing fields"))

    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE username = (%s)", (username,))
        user = cur.fetchone()
    finally:
        close_database(conn, cur)


    if user is None:
        return redirect(url_for('login', error="Username or password was incorect"))

    if check_password_hash(user[3], password):
        response = make_response(redirect(url_for("home_user")))
        jwtoken = jwt.encode({"user_id" : user[0], "exp" : datetime.now(UTC) + timedelta(hours=1)}, os.getenv('JWTSECRET'), algorithm="HS256")
        response.set_cookie("access_token", jwtoken, httponly=True, samesite="Lax", secure=not app.debug, max_age=3600)
        return response
    
    return redirect(url_for('login', error="Username or password was incorect"))
    
    


@app.route("/signup_submit", methods=["POST"])
def signup_submit():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return redirect(url_for('signup', error="Please complete CAPTCHA"))
    
    if not verify_token(captcha_token):
        return redirect(url_for('signup', error="CAPTCHA failed"))
    
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    hashed_password = generate_password_hash(password)

    if len(username) <= 5:
        return redirect(url_for('signup', error="Username is too short"))
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return redirect(url_for('signup', error="Email is not valid"))
    if len(password) < 8:
        return redirect(url_for('signup', error="Password id too short"))
    if not re.match(r'^[A-Za-z0-9_*]+$', password):
        return redirect(url_for('signup', error="Cannot update password - new password is not valid (password can only contain letters, numbers, '_', and '*')"))

    conn, cur = None, None
    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE username = (%s)", (username,)) 

        if cur.fetchone() is not None:
            return redirect(url_for('signup', error="Username is already in use"))

        cur.execute("INSERT INTO users (username, email, password, google_id) VALUES (%s, %s, %s, %s) RETURNING id", (username, email, hashed_password, None))
        user_id = cur.fetchone()[0]
        print(conn)
        if conn:
            conn.commit()
    finally:
        close_database(conn, cur)

    response = make_response(redirect(url_for("home_user")))
    jwtoken = jwt.encode({"user_id" : user_id, "exp" : datetime.now(UTC) + timedelta(hours=1)}, os.getenv('JWTSECRET'), algorithm="HS256")
    response.set_cookie("access_token", jwtoken, httponly=True, samesite="Lax", secure=not app.debug,  max_age=3600)
    
    return response

@app.route("/google_auth")
def google_auth():
    return google.authorize_redirect(
        url_for("google_callback", _external=True)
    )

@app.route("/auth/google/callback", methods=["POST"])
def google_callback():
    
    token = google.authorize_access_token()
    user_info = token["userinfo"]
    print(user_info)
    # return "success"
    
    google_id = user_info["sub"]
    email = user_info["email"]

    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE google_id = (%s)", (google_id,)) 
        user = cur.fetchone()

        if user is not None: # Already exists -> login
            user_id = user[0]
        else:
            cur.execute("INSERT INTO users (username, email, password, google_id) VALUES (%s, %s, %s, %s) RETURNING id", (None, email, None, google_id))
            user_id = cur.fetchone()[0]
    finally:
        if conn:
            conn.commit()
        close_database(conn, cur)

    response = make_response(redirect(url_for("home_user")))
    jwtoken = jwt.encode({"user_id" : user_id, "exp" : datetime.now(UTC) + timedelta(hours=1)}, os.getenv('JWTSECRET'), algorithm="HS256")
    response.set_cookie("access_token", jwtoken, httponly=True, samesite="Lax", secure=not app.debug,  max_age=3600)
    
    return response


def get_data_from_token():
    jwtoken = request.cookies.get("access_token")
    try:
        data = jwt.decode(jwtoken, os.getenv('JWTSECRET'), algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return False
    return data
        

def get_user_from_user_id(user_id):
    user = None
    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE id = (%s)", (user_id,)) 
        user = cur.fetchone()
    finally:
        close_database(conn, cur)
    
    return user

@app.route("/home_user")
def home_user():

    data = get_data_from_token()
    if not data:
        return redirect(url_for("login"))

    user = get_user_from_user_id(data["user_id"])

    username, email, created_at = user[1], user[2], user[5]
    google_id = user[4]

    return safe_render_template("home_user.html", {"user_id" : data["user_id"], "username" : username, "email" : email, "created_at" : created_at})


@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("home"))
    response.delete_cookie("access_token")
    return response

@app.route("/settings")
def settings():
    error, success = request.args.get("error"), request.args.get("success")

    data = get_data_from_token()
    if not data:
        return redirect(url_for("login"))
    
    user = get_user_from_user_id(data["user_id"])
    username, email, created_at = user[1], user[2], user[5]

    return safe_render_template("settings_user.html", {"user_id" : data["user_id"], "username" : username, "email" : email, "created_at" : created_at, "error" : error, "success" : success})

@app.route("/update_email", methods=["POST"])
def update_email():
    data = get_data_from_token()
    if not data:
        return redirect(url_for("login"))
    
    user = get_user_from_user_id(data["user_id"])
    username, email, created_at, google_id = user[1], user[2], user[5], user[4]

    if google_id:
        return redirect(url_for("settings", error="Cannot update email for this user (used OAuth 2.0)"))

    password = request.form.get("password", "")
    new_email = request.form.get("new_email", "").strip().lower()

    if not new_email or not password:
        return redirect(url_for('settings', error="Cannot update email - missing fields"))
    
    if email == new_email:
        return redirect(url_for('settings', error="Cannot update email - this is already your email, nothing to update"))
    
    if not check_password_hash(user[3], password):
        return redirect(url_for('settings', error="Cannot update email - password is not valid"))
    
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', new_email):
        return redirect(url_for('settings', error="Cannot update email - email is not valid"))  
    
    try:
        conn, cur = connect_to_database()
        cur.execute("UPDATE users SET email = (%s) WHERE id = (%s)", (new_email, user[0])) 
        conn.commit()
    except psycopg.errors.UniqueViolation:
        conn.rollback()
        return redirect(url_for('settings', error="Cannot update email - this email is already in use"))
    finally:
        close_database(conn, cur)
    
    return redirect(url_for('settings', success="Email updated"))


@app.route("/update_password", methods=["POST"])
def update_password():
    data = get_data_from_token()
    if not data:
        return redirect(url_for("login"))
    
    user = get_user_from_user_id(data["user_id"])
    username, email, created_at, google_id = user[1], user[2], user[5], user[4]

    if google_id:
        return redirect(url_for("settings", error="Cannot update password for this user (used OAuth 2.0)"))
    
    password = request.form.get("password", "")
    new_password = request.form.get("new_password", "")
    hashed_password = generate_password_hash(new_password)

    if not new_password or not password:
        return redirect(url_for('settings', error="Cannot update password - missing fields"))
    
    if not check_password_hash(user[3], password):
        return redirect(url_for('settings', error="Cannot update password - password is not valid"))
    
    if password == new_password:
        return redirect(url_for('settings', error="Cannot update password - this is already your password, nothing to update"))
    
    if len(new_password) < 8:
        return redirect(url_for('settings', error="Cannot update password - new password is not valid (too short)"))
    if not re.match(r'^[A-Za-z0-9_*]+$', new_password):
        return redirect(url_for('settings', error="Cannot update password - new password is not valid (password can only contain letters, numbers, '_', and '*')"))
    
    try:
        conn, cur = connect_to_database()
        cur.execute("UPDATE users SET password = (%s) WHERE id = (%s)", (hashed_password, user[0])) 
        conn.commit()
    finally:
        close_database(conn, cur)
    
    return redirect(url_for('settings', success="Password updated"))


@app.route("/forgot_password")
def forgot_password():
    error = request.args.get("error")
    return safe_render_template("forgot_password.html", {"error" : error})

def send_reset_email(to_email, reset_link):
    msg = Message("Reset your password", recipients=[to_email])
    msg.body = f"Click to reset your password (expires in 5 minutes): {reset_link}"
    msg.html = f'<p>Click below to reset your password. This link expires in 5 minutes.</p><a href="{reset_link}">Reset Password</a>'
    mail.send(msg)

@app.route("/send_password_reset_email", methods=["POST"])
def send_password_reset_email():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return redirect(url_for('forgot_password', error="Please complete CAPTCHA"))
    
    if not verify_token(captcha_token):
        return redirect(url_for('forgot_password', error="CAPTCHA failed"))

    email = request.form.get("email")
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    main_domain = os.getenv("MAIN_DOMAIN")
    reset_link = f"https://{main_domain}/reset_password_link?token={raw_token}"
    expires_at = datetime.now(UTC) + timedelta(minutes=5)

    if not email:
        return redirect(url_for('forgot_password', error="Cannot send password reset link - Email field is empty"))
    
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return redirect(url_for('forgot_password', error="Cannot send password reset link to unvalid email"))

    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE email = (%s)", (email, )) 
        user = cur.fetchone()
    finally:
        close_database(conn, cur)

    if not user:
        return redirect(url_for('forgot_password', error="Cannot send password reset link to nonexistent email"))

    try:
        conn, cur = connect_to_database()
        cur.execute("UPDATE password_resets SET used = TRUE WHERE user_id = %s AND used = FALSE", (user[0],))
        cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (user[0], token_hash, expires_at)) 
        conn.commit()
    finally:
        close_database(conn, cur)
    send_reset_email(email, reset_link)

    return redirect(url_for("email_was_sent"))



@app.route("/email_was_sent")
def email_was_sent():
    return safe_render_template("email_was_sent.html")


def is_token_valid(cur, raw_token):
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    cur.execute("SELECT user_id FROM password_resets WHERE token_hash = (%s) AND expires_at > NOW() AND used = FALSE", (token_hash, ))
    row = cur.fetchone()
    return row, token_hash


@app.route("/reset_password_link", methods=["GET", "POST"])
def reset_password_link():
    if request.method == "GET":
        error = request.args.get("error")
        raw_token = request.args.get("token")
        
    else:
        raw_token = request.form.get("token")

    print(f"[DEBUG] sdfdf {raw_token},", flush=True)

    if not raw_token:
        return redirect(url_for('forgot_password', error="Reset link is invalid please try again"))

    try:
        conn, cur = connect_to_database()
        row, token_hash = is_token_valid(cur, raw_token)

        print(f"[DEBUG] completed {token_hash}, {row}, {not row}", flush=True)

        if not row:
            return redirect(url_for('forgot_password', error="Reset link is invalid please try again"))

        if request.method == "GET":
            return safe_render_template("reset_password.html", {"token" : raw_token, "error" : error})


        captcha_token = request.form.get("h-captcha-response")
        new_password = request.form.get("password")
        hashed_password = generate_password_hash(new_password)

        if not captcha_token:
            return redirect(url_for('reset_password_link', token=raw_token, error="Please complete CAPTCHA"))

        if not verify_token(captcha_token):
            return redirect(url_for('reset_password_link', token=raw_token, error="CAPTCHA failed"))

        if not new_password:
            return redirect(url_for('reset_password_link', token=raw_token, error="Cannot reset password - that field cannot be empty"))
        if len(new_password) < 8:
            return redirect(url_for('reset_password_link', token=raw_token, error="Cannot reset password - new password is not valid (too short)"))
        if not re.match(r'^[A-Za-z0-9_*]+$', new_password):
            return redirect(url_for('reset_password_link', token=raw_token, error="Cannot reset password - new password is not valid (password can only contain letters, numbers, '_', and '*')"))

        try:
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, row[0]))
            cur.execute("UPDATE password_resets SET used = TRUE WHERE token_hash = %s", (token_hash,))
            conn.commit()
        except Exception as e:
            print("Error while changing psw:", e)
            return redirect(url_for('reset_password_link', token=raw_token, error="Something went wrong - not your fault( Try again!"))
    finally:
        close_database(conn, cur)
    print("[DEBUG] completed")
    return redirect(url_for("password_was_reset"))

        

@app.route("/password_was_reset")
def password_was_reset():
    return safe_render_template("password_was_reset.html")
        
    


