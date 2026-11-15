from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from datetime import timedelta
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect, generate_csrf
import os

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)

# -------------------------
# Session & CSRF security
# -------------------------
# NOTE: in production this key should be static and secret, not regenerated each run.
app.secret_key = os.urandom(32)

app.permanent_session_lifetime = timedelta(minutes=3)

app.config.update(
    SESSION_COOKIE_SECURE=True,      # Only over HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # Not accessible to JS
    SESSION_COOKIE_SAMESITE="Lax",   # Helps mitigate CSRF
    WTF_CSRF_TIME_LIMIT=None         # Tokens valid for session lifetime
)

csrf = CSRFProtect(app)


@app.context_processor
def inject_csrf_token():
    """
    Makes csrf_token() available in templates.
    Usage in HTML:
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    """
    return dict(csrf_token=generate_csrf)


client = MongoClient("mongodb://localhost:27017/")
db = client['user_database']
users_collection = db['users']
wallets_collection = db['wallets']


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/info')
def info():
    return render_template('info.html')


@app.route('/secret_page')
def secret():
    if 'username' not in session:
        return redirect(url_for('login_page'))  # Redirect to login if not authenticated

    return render_template('secret.html', username=session['username'])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        username = (data.get('username') or "").strip()
        password = data.get('password') or ""

        # Basic input validation
        if not username or not password:
            return render_template(
                'register.html',
                error="Username and password are required."
            )

        if len(username) < 3:
            return render_template(
                'register.html',
                error="Username must be at least 3 characters."
            )

        if len(password) < 6:
            return render_template(
                'register.html',
                error="Password must be at least 6 characters."
            )

        if users_collection.find_one({"username": username}):
            return render_template(
                'register.html',
                error="User already exists. Please choose another username."
            )

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {"username": username, "password_hash": hashed_password}
        users_collection.insert_one(user)

        # Redirect to the login page after successful registration
        return redirect(url_for('login_page'))

    # GET -> registration form
    return render_template('register.html', error=None)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        username = (data.get('username') or "").strip()
        password = data.get('password') or ""

        if not username or not password:
            return render_template(
                'login.html',
                error="Username and password are required."
            )

        user = users_collection.find_one({"username": username})

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session.permanent = True  # Enable permanent sessions
            session['username'] = username
            return redirect(url_for('index'))

        return render_template(
            'login.html',
            error="Invalid username or password."
        )

    # Render the login form for GET requests
    return render_template('login.html', error=None)


# Route to show Create Wallet form (only accessible if logged in)
@app.route('/create_wallet_page', methods=['GET'])
def create_wallet_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    return render_template('create_wallet.html',
                           username=session['username'],
                           error=None)


# Function to create a wallet (requires user to be logged in)
@app.route('/create_wallet', methods=['POST'])
def create_wallet():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    initial_balance_raw = (request.form.get('initial_balance') or "").strip()

    # TODO completed: input validation
    # Make sure the user is giving a number and the value is >= 0.
    try:
        initial_balance = float(initial_balance_raw)
        if initial_balance < 0:
            raise ValueError("Balance must be non-negative")
    except ValueError:
        return render_template(
            'create_wallet.html',
            username=session['username'],
            error="Initial balance must be a non-negative number."
        ), 400

    # Check if the wallet already exists for the logged-in user
    existing_wallet = wallets_collection.find_one({"username": session['username']})
    if existing_wallet:
        return render_template(
            'create_wallet.html',
            username=session['username'],
            error="Wallet already exists for this user."
        ), 400

    # Create wallet for the user
    wallet = {"username": session['username'], "balance": float(initial_balance)}
    wallets_collection.insert_one(wallet)

    return redirect(url_for('show_wallet'))


@app.route('/show_wallet', methods=['GET'])
def show_wallet():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    # TODO completed: fetch wallet for this username
    wallet = wallets_collection.find_one({"username": session['username']})

    if not wallet:
        return "Wallet does not exist. Please create one first.", 404

    balance = wallet['balance']
    return render_template('show_wallet.html',
                           username=session['username'],
                           balance=balance)


@app.route('/add_money', methods=['GET', 'POST'])
def add_money():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if request.method == 'GET':
        wallet = wallets_collection.find_one({"username": session['username']})
        if not wallet:
            return "Wallet does not exist. Please create one first.", 404

        return render_template(
            'add_money.html',
            balance=wallet['balance'],
            username=session['username'],
            success=None,
            error=None
        )

    # POST: process adding money
    amount_raw = (request.form.get('amount') or "").strip()

    wallet = wallets_collection.find_one({"username": session['username']})
    if not wallet:
        return "Wallet does not exist. Please create one first.", 404

    try:
        amount = float(amount_raw)
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except ValueError:
        return render_template(
            'add_money.html',
            balance=wallet['balance'],
            username=session['username'],
            error="Invalid amount. Please enter a positive number.",
            success=None
        )

    wallets_collection.update_one(
        {"username": session['username']},
        {"$inc": {"balance": amount}}
    )

    return render_template(
        'add_money.html',
        balance=wallet['balance'] + amount,
        username=session['username'],
        success=f"Successfully added ${amount} to your wallet.",
        error=None
    )


@app.route('/transfer_money', methods=['GET', 'POST'])
def transfer_money():
    # TODO completed: add a session check
    if 'username' not in session:
        return redirect(url_for('login_page'))

    username = session['username']

    # GET: show form
    if request.method == 'GET':
        wallet = wallets_collection.find_one({"username": username})
        if not wallet:
            return "Wallet does not exist. Please create one first.", 404

        return render_template(
            'transfer_money.html',
            balance=wallet['balance'],
            username=username,
            success=None,
            error=None
        )

    # POST: process transfer
    recipient_username = (request.form.get('recipient') or "").strip()
    amount_raw = (request.form.get('amount') or "").strip()

    sender_wallet = wallets_collection.find_one({"username": username})
    if not sender_wallet:
        return "Wallet does not exist. Please create one first.", 404

    # Validate amount
    try:
        amount = float(amount_raw)
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except ValueError:
        return render_template(
            'transfer_money.html',
            balance=sender_wallet['balance'],
            username=username,
            error="Invalid amount. Please enter a positive number.",
            success=None
        )

    # Additional validation: recipient cannot be empty or self
    if not recipient_username:
        return render_template(
            'transfer_money.html',
            balance=sender_wallet['balance'],
            username=username,
            error="Recipient username is required.",
            success=None
        )

    if recipient_username == username:
        return render_template(
            'transfer_money.html',
            balance=sender_wallet['balance'],
            username=username,
            error="You cannot transfer money to yourself.",
            success=None
        )

    # TODO completed: insufficient balance handling
    if sender_wallet['balance'] < amount:
        return render_template(
            'transfer_money.html',
            balance=sender_wallet['balance'],
            username=username,
            error="Insufficient balance for this transfer.",
            success=None
        )

    # Check if the recipient exists
    recipient_wallet = wallets_collection.find_one({"username": recipient_username})
    if not recipient_wallet:
        return render_template(
            'transfer_money.html',
            balance=sender_wallet['balance'],
            username=username,
            error=f"No wallet found for recipient '{recipient_username}'.",
            success=None
        )

    # Perform atomic-ish update (two separate Mongo updates)
    wallets_collection.update_one(
        {"username": username},          # Deduct from sender
        {"$inc": {"balance": -amount}}
    )
    wallets_collection.update_one(
        {"username": recipient_username},  # Add to recipient
        {"$inc": {"balance": amount}}
    )

    updated_sender_balance = sender_wallet['balance'] - amount

    return render_template(
        'transfer_money.html',
        balance=updated_sender_balance,
        username=username,
        success=f"Successfully transferred ${amount} to {recipient_username}.",
        error=None
    )


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login_page'))


if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=3009)