import os
from flask import Flask, render_template, request
import requests
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

@app.route("/")
def home():
    try:
        return render_template("home_page.html")
    except:
        return render_template("error.html")

@app.route("/login")
def login():
    try:
        return render_template("login.html")
    except:
        return render_template("error.html")

@app.route("/signup")
def signup():
    try:
        return render_template("home_signuppage.html")
    except:
        return render_template("error.html")
    

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

@app.route("/login_submit", methods=["POST"])
def login_submit():
    captcha_token = request.form.get("h-captcha-response")
    
    if not captcha_token:
        return "Please complete CAPTCHA", 400
    
    if not verify_token(captcha_token):
        return "CAPTCHA failed", 400
    
    username = request.form.get("username")
    password = request.form.get("password")
    
    return "Login ok"