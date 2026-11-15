from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from datetime import timedelta
from flask_socketio import SocketIO, emit, disconnect
import os


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)

# Set a secret key for session management
app.secret_key = os.urandom(24)  # Generate a random secret key

app.permanent_session_lifetime = timedelta(minutes=5)  # Set session lifetime to 1 minutes

# Connection to MongoDB database
client = MongoClient("mongodb://localhost:27017/")
db = client['user_database'] # user_database is the database name
users_collection = db['users'] # users is the table name

# TODO: add your info.html call. Was in part 1. You need to modify home.html.
# Check home.html for instructions.
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/info')
def info():
    # DONE: add your info.html call. Was in part 1.
    return render_template('info.html')

# New secret page
@app.route('/secret_page')
def secret():
    # The following check is for validating the username in the current sessions.
    if 'username' not in session:
        return redirect(url_for('login_page'))  # Redirect to login if not authenticated
    
    return render_template('secret.html', username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form  # using form data
        username = data.get('username')
        # TODO: Write a line to take the password from the password field
        password = data.get('password')

        if users_collection.find_one({"username": username}):
            # TODO: Write a message in the following line to show some message 
            # to the user that user already exists
            return jsonify({'message': 'User already exists'}), 400

        # TODO: Use your password variable in the following line 
        # inside the generate_password_hash function
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {"username": username, "password_hash": hashed_password}
        # TODO: use your users_collection variable (defined earlier) to 
        # call insert_one function to insert the info of user variable.
        users_collection.insert_one(user)

        # Redirect to the login page after successful registration
        # TODO: Call the login_page function in the following return
        # statement. Use the definition (login_page) to call the login page.
        return redirect(url_for('login_page'))

    # Render the registration form for GET requests
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        # TODO: Define two variables named username and password, and
        # assign the values using data variable. You need to write 
        # similar lines like the register function.
        username = data.get('username')
        password = data.get('password')

        user = users_collection.find_one({"username": username})

        # TODO *: The following line will check the password. If the password 
        # is correct, it will execute the lines inside the if condition. 
        # You need to put your password and username variable in the following part.
        # TODO *a: put your password variable after comma in the following line 
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session.permanent = True  
            # TODO *b: put your username variable in the following line
            session['username'] = username
            #TODO: redirect to your secret page after login
            return redirect(url_for('secret'))

        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Render the login form for GET requests
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    # Redirect to the login page after logging out
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    # Run HTTP and HTTPS servers in parallel using threading
    socketio.run(app, host='127.0.0.1', port=3009)
