import os
from flask import Flask, render_template, request, redirect, url_for
import requests
from dotenv import load_dotenv
import psycopg

load_dotenv()
app = Flask(__name__)

def safe_render_template(template_file):
    try:
        return render_template(template_file)
    except:
        return render_template("error.html")

def connect_to_data_base():
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
    conn.commit()
    return (conn, cur)

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
    return safe_render_template("login.html")

@app.route("/signup")
def signup():
    return safe_render_template("signup.html")

@app.route("/login_submit", methods=["POST"])
def login_submit():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return "Please complete CAPTCHA", 400
    
    if not verify_token(captcha_token):
        return "CAPTCHA failed", 400
    
    username = request.form.get("username")
    password = request.form.get("password")

    conn, cur = connect_to_data_base()

    cur.execute("SELECT * FROM users WHERE name = (%s)", (username,))
    print(cur.fetchall())

    conn.commit()
    conn.close()
    
    return "Login ok"

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

    conn, cur = connect_to_data_base()

    # Check whether user data is correct (NEEDS IMPLEMENTATION)

    cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (username, email, password))

    conn.commit()
    conn.close()
    
    return redirect(url_for('home_user'))


@app.route("/home_user")
def home_user():
    return safe_render_template("home_user.html")