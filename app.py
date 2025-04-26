from flask import Flask, request, redirect, session
import sqlite3
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv(dotenv_path='./config/.env')

# Configure logging
logging.basicConfig(
    filename='login_activity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))


def get_db_connection():
    return sqlite3.connect('users.db')


# Route: Home Page with Login Form
@app.route('/', methods=['GET'])
def home():
    return '''
        <h2>Welcome to the Secure Login App</h2>
        <form method="POST" action="/login">
            Username: <input type="text" name="username" /><br>
            Password: <input type="password" name="password" /><br>
            <input type="submit" value="Login" />
        </form>
    '''


# Route: Handle Login Submission
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    conn.close()

    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    if result:
        session['user'] = username
        logging.info(f"Login successful | User: {username} | IP: {ip} | Browser: {user_agent}")
        return redirect('/dashboard')
    else:
        logging.warning(f"Login failed | User: {username} | IP: {ip} | Browser: {user_agent}")
        return "Login failed. Please check your username and password."


# Route: Dashboard (Protected Page)
@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"<h3>Welcome {session['user']}!</h3><br><a href='/logout'>Logout</a>"
    else:
        return redirect('/')


# Route: Logout
@app.route('/logout')
def logout():
    username = session.get('user', 'Unknown')
    session.clear()
    logging.info(f"User logged out: {username}")
    return redirect('/')


# Create test user if not exists
def create_test_user():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Check if admin user already exists
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", "password123"))
        conn.commit()
        logging.info("Test user 'admin' created.")
    conn.close()


# Initialize database with test user
create_test_user()

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
