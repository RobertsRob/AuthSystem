import os
import re
from flask import Flask, render_template, request, redirect, url_for, make_response
import requests
from dotenv import load_dotenv
import psycopg
import jwt
from datetime import datetime, timedelta, UTC
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app = Flask(__name__)

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
        name TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        password TEXT NOT NULL)
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


@app.route("/")
def home():
    return safe_render_template("home_page.html")

@app.route("/login")
def login():
    error = request.args.get("error")
    return safe_render_template("login.html", {"error" : error})

@app.route("/signup")
def signup():
    error = request.args.get("error")
    return safe_render_template("signup.html", {"error" : error})

@app.route("/login_submit", methods=["POST"])
def login_submit():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return "Please complete CAPTCHA", 400
    
    if not verify_token(captcha_token):
        return "CAPTCHA failed", 400
    
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return redirect(url_for('login', error="Missing fields"))

    try:
        conn, cur = connect_to_database()
        cur.execute("SELECT * FROM users WHERE name = (%s)", (username,))
        user = cur.fetchone()
    finally:
        close_database(conn, cur)


    if user is None:
        return redirect(url_for('login', error="Username or password was incorect"))

    if check_password_hash(user[3], password):
        response = make_response(redirect(url_for("home_user")))
        jwtoken = jwt.encode({"user_id" : user[0], "exp" : datetime.now(UTC) + timedelta(hours=1)}, os.getenv('JWTSECRET'), algorithm="HS256")
        response.set_cookie("access_token", jwtoken, httponly=True, samesite="Strict", secure=not app.debug, max_age=3600)
        return response
    
    return redirect(url_for('login', error="Username or password was incorect"))
    
    


@app.route("/signup_submit", methods=["POST"])
def signup_submit():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return "Please complete CAPTCHA", 400
    
    if not verify_token(captcha_token):
        return "CAPTCHA failed", 400
    
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
        cur.execute("SELECT * FROM users WHERE name = (%s)", (username,)) 

        if cur.fetchone() is not None:
            return redirect(url_for('signup', error="Username is already in use"))

        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s) RETURNING id", (username, email, hashed_password))
        user_id = cur.fetchone()[0]
    finally:
        if conn:
            conn.commit()
        close_database(conn, cur)

    response = make_response(redirect(url_for("home_user")))
    jwtoken = jwt.encode({"user_id" : user_id, "exp" : datetime.now(UTC) + timedelta(hours=1)}, os.getenv('JWTSECRET'), algorithm="HS256")
    response.set_cookie("access_token", jwtoken, httponly=True, samesite="Strict", secure=not app.debug,  max_age=3600)
    
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

    return safe_render_template("home_user.html", {"user_id" : data["user_id"], "username" : username, "email" : email})