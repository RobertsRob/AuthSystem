from flask import Flask, render_template

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