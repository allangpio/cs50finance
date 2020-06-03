import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
#Create a transaction Table
db.execute("CREATE TABLE IF NOT EXISTS 'transactions' ('trans_id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'user_id' INT, 'symbol' TEXT, name 'TEXT', 'shares' INT, 'price' NUMERIC, 'total' NUMERIC NOT NULL, 'time' DATETIME NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)");


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get('symbol'):
            return apology('missing symbol', 400)

        symbol = request.form.get('symbol')
        session['stock'] = lookup(symbol)

        if session['stock'] == None:
            return apology('invalid symbol', 400)

        session['shares'] = int(request.form.get('shares'))
        if session['shares'] <=0:
            return apology('number of shares must be positive', 400)

        session['cash'] = db.execute("SELECT cash from transactions WHERE username = :username", username=session['user_id'])





    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    if request.method == 'POST':
        symbol = request.form.get('symbol')
        session['stock'] = lookup(symbol)
        if session['stock'] == None:
            return apology("invalid symbol", 400)

        session['stock']['price'] = usd(session['stock']['price'])
        return render_template("quoted.html", stock = session['stock'])




    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username is available
        if len(rows) == 1:
            return flash('This username is not available')


        session['username'] = request.form.get("username")

        session['password'] = request.form.get("password")
        session['confirmation'] = request.form.get("confirmation")

        #Verify if passwords are equal
        if session['password'] != session['confirmation']:
            return apology("password don't match", 400)

        # Hash the user's password
        session['hash'] = generate_password_hash(session['password'], method='pbkdf2:sha256', salt_length=8)


        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username = session['username'], hash = session['hash'])
        flash("You've been succefully registered!")

        return redirect("/")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
