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

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

oauth = OAuth(app)

try:
    google = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_AUTH_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_AUTH_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={ "scope": "openid email profile" }
    )
except Exception as e:
    print(f"Failed to connect to google auth: {e}")

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
            dbname="postgres",
            user="postgres",
            password=f"{os.getenv('POSTGRES')}",
            host="localhost",
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
    finally:
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
    
    username = request.form.get("username")
    password = request.form.get("password")

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
    
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    hashed_password = generate_password_hash(password)

    if len(username) <= 5:
        return redirect(url_for('signup', error="Username is too short"))
    if not re.match(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$', email):
        return redirect(url_for('signup', error="Email is not valid"))
    if len(password) < 8:
        return redirect(url_for('signup', error="Password id too short"))

    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE username = (%s)", (username,)) 

        if cur.fetchone() is not None:
            return redirect(url_for('signup', error="Username is already in use"))

        cur.execute("INSERT INTO users (username, email, password, google_id) VALUES (%s, %s, %s, %s) RETURNING id", (username, email, hashed_password, None))
        user_id = cur.fetchone()[0]
    finally:
        if conn:
            conn.commit()
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

@app.route("/auth/google/callback")
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


# {os.getenv('JWTSECRET')}

@app.route("/home_user")
def home_user():

    jwtoken = request.cookies.get("access_token")
    
    try:
        data = jwt.decode(jwtoken, os.getenv('JWTSECRET'), algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return redirect(url_for("login"))
    
    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE id = (%s)", (data["user_id"],)) 
        user = cur.fetchone()
    finally:
        close_database(conn, cur)

    username = user[1]
    email = user[2]
    encrypted_psw = user[3]
    google_id = user[4]
    created_at = user[5]

    return safe_render_template("home_user.html", {"user_id" : data["user_id"], "username" : username, "email" : email, "google_id" : google_id, "created_at" : created_at})


@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("home"))
    response.delete_cookie("access_token")
    return response