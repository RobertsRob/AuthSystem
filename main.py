from flask import Flask, render_template
import requests

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
    

def verify_token(token, ip):
    data = {
        "secret": "",
        "response": token,
        "remoteip": ip,
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