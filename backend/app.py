from flask import Flask, request, render_template, redirect, url_for, session, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import logging
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import re  # Import the re module for regex operations

# Create the Flask app and configure templates and static folders
app = Flask(__name__, template_folder='templates', static_folder='../static')
logging.basicConfig(filename='app.log', level=logging.ERROR)

# Set a secret key for session management (should be kept secret in production)
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page when not logged in

# User data dictionary (for demo purposes; use a database in production)
users = {
    "user1": generate_password_hash("password1"),  # Storing hashed passwords
    "user2": generate_password_hash("password2"),
}

# Format key to 32 bytes (256 bits) for AES encryption
def format_key(key):
    return key.ljust(32)[:32]

# Encrypt a message using AES encryption
def encrypt_message(key, message):
    key = format_key(key)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

# Decrypt a message using AES decryption
def decrypt_message(key, encrypted):
    key = format_key(key)
    encrypted = base64.b64decode(encrypted)
    iv = encrypted[:16]
    ct = encrypted[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Home route that renders index.html
@app.route('/')
@login_required  # Protect home route
def home():
    return render_template('index.html')

# Route for encrypting a message
@app.route('/encrypt', methods=['POST'])
@login_required  # Protect encrypt route
def encrypt():
    key = request.form['key']
    message = request.form['message']
    
    if len(key) < 16:
        return "Key must be at least 16 characters long.", 400  # Return error with HTTP 400 status
    
    encrypted = encrypt_message(key, message)
    return render_template('index.html', encrypted_message=encrypted)

# Route for decrypting a message
@app.route('/decrypt', methods=['POST'])
@login_required  # Protect decrypt route
def decrypt():
    key = request.form['key']
    encrypted_message = request.form['encrypted_message']
    
    try:
        decrypted = decrypt_message(key, encrypted_message)
        return render_template('index.html', decrypted_message=decrypted)
    except Exception as e:
        return f"Error during decryption: {str(e)}", 400  # Handle decryption error

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            flash("Username already exists. Please choose a different one.")
            return redirect(url_for('register'))
        
        users[username] = generate_password_hash(password)  # Hash the password
        flash("Successfully registered! Please log in.")  # Flash success message
        return redirect(url_for('login'))
    return render_template('register.html')


# Login route that handles GET and POST requests
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username], password):
            user = User()
            user.id = username
            login_user(user)
            flash("Login successful!")  # Flash success message
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials. Please try again.")  # Flash error message
            return redirect(url_for('login'))
    return render_template('login.html')


# Flask-Login user class for session management
class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:  # Check if user ID is valid
        user = User()
        user.id = user_id
        return user
    return None

# Logout route that redirects to home after logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Use logout_user to handle session properly
    return redirect(url_for('login'))  # Redirect to login page after logout

# Custom error handler for logging exceptions
@app.errorhandler(Exception)
def handle_error(e):
    logging.error(f"Error occurred: {str(e)}")
    return "An error occurred", 500

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
