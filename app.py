from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import random
import string
import os
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)

# MongoDB Connection
client = MongoClient('mongodb://localhost:27017/')
db = client['Real-Time-Chat-App']
users_collection = db['users']

# Email Configuration
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

# Store active rooms with their participants
rooms = {}

# WhatsApp-like colors for usernames
USER_COLORS = [
    '#FF6B6B', '#4ECDC4', '#f7e705', 
    '#A06CD5', '#79D45E', '#f79605'
]

def generate_unique_code():
    """Generate a unique 6-digit code that isn't already in use."""
    while True:
        code = ''.join(random.choices(string.digits, k=6))
        if code not in rooms:
            return code

def get_user_color(username):
    """Generate a consistent color for a username."""
    # Create a hash of the username
    hash_value = int(hashlib.md5(username.encode()).hexdigest(), 16)
    # Use the hash to select a color
    return USER_COLORS[hash_value % len(USER_COLORS)]

def generate_otp():
    """Generate a 6-digit OTP code."""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email, otp):
    """Send verification email with OTP."""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = email
        msg['Subject'] = 'Connect Chat - Email Verification'
        
        body = f"""
        <html>
          <body>
            <h2>Welcome to Connect Chat!</h2>
            <p>Your verification code is: <strong>{otp}</strong></p>
            <p>This code will expire in 10 minutes.</p>
          </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        existing_user = users_collection.find_one({"$or": [
            {"username": username},
            {"email": email}
        ]})
        
        if existing_user:
            if existing_user.get('username') == username:
                return render_template('signup.html', error="Username already exists")
            else:
                return render_template('signup.html', error="Email already registered")
                
        # Generate OTP
        otp = generate_otp()
        otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        
        # Create new user with pending verification
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "verified": False,
            "otp": otp,
            "otp_expiry": otp_expiry
        }
        
        # Send verification email
        if send_verification_email(email, otp):
            users_collection.insert_one(new_user)
            # Store email in session for verification page
            session['verify_email'] = email
            return redirect(url_for('verify'))
        else:
            return render_template('signup.html', error="Failed to send verification email. Please try again.")
    
    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'verify_email' not in session:
        return redirect(url_for('signup'))
    
    email = session['verify_email']
    
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        
        user = users_collection.find_one({"email": email})
        
        if not user:
            flash("User not found", "error")
            return redirect(url_for('signup'))
        
        if user.get('otp') != entered_otp:
            return render_template('verify.html', error="Invalid OTP code")
        
        if datetime.datetime.utcnow() > user.get('otp_expiry'):
            return render_template('verify.html', error="OTP has expired. Please request a new one.")
        
        # Update user verification status
        users_collection.update_one(
            {"email": email},
            {"$set": {"verified": True, "otp": None, "otp_expiry": None}}
        )
        
        flash("Account verified successfully! Please login.", "success")
        session.pop('verify_email', None)
        return redirect(url_for('login'))
    
    return render_template('verify.html', email=email)

@app.route('/resend-otp')
def resend_otp():
    if 'verify_email' not in session:
        return redirect(url_for('signup'))
    
    email = session['verify_email']
    user = users_collection.find_one({"email": email})
    
    if not user:
        session.pop('verify_email', None)
        return redirect(url_for('signup'))
    
    # Generate new OTP
    otp = generate_otp()
    otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    
    # Update user with new OTP
    users_collection.update_one(
        {"email": email},
        {"$set": {"otp": otp, "otp_expiry": otp_expiry}}
    )
    
    # Send verification email
    if send_verification_email(email, otp):
        flash("New OTP sent successfully", "success")
    else:
        flash("Failed to send OTP. Please try again.", "error")
    
    return redirect(url_for('verify'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_collection.find_one({"username": username})
        
        if not user or not bcrypt.check_password_hash(user['password'], password):
            return render_template('login.html', error="Invalid username or password")
        
        if not user['verified']:
            session['verify_email'] = user['email']
            return redirect(url_for('verify'))
        
        # Set session variables
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['email'] = user['email']
        
        return redirect(url_for('home'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear session data
    session.clear()
    return redirect(url_for('index'))

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        join = request.form.get('join', False)
        create = request.form.get('create', False)
        
        if join and not code:
            return render_template('home.html', error="Please enter a room code.")
        
        # Store the room code in session
        session['room'] = code
        
        # Create a new room
        if create:
            room_code = generate_unique_code()
            rooms[room_code] = {"members": 0, "messages": []}
            session['room'] = room_code
            return redirect(url_for('room'))
        
        # Join an existing room
        if code not in rooms:
            return render_template('home.html', error="Room does not exist.")
        
        return redirect(url_for('room'))
    
    return render_template('home.html', username=session.get('username'))

@app.route('/room')
def room():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    room = session.get('room')
    username = session.get('username')
    
    if not room or room not in rooms:
        return redirect(url_for('home'))
    
    return render_template('room.html', room=room, name=username, messages=rooms[room]["messages"], get_user_color=get_user_color)

@socketio.on('connect')
def handle_connect():
    room = session.get('room')
    username = session.get('username')
    
    if not room or not username:
        return
    
    if room not in rooms:
        rooms[room] = {"members": 0, "messages": []}
    
    join_room(room)
    rooms[room]["members"] += 1
    
    # Send join notification to room
    send({
        "name": username,
        "message": "has entered the room"
    }, to=room)
    
    print(f"{username} joined room {room}")

@socketio.on('disconnect')
def handle_disconnect():
    room = session.get('room')
    username = session.get('username')
    
    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
        else:
            # Send leave notification to room
            leave_room(room)
            send({
                "name": username,
                "message": "has left the room"
            }, to=room)
    
    print(f"{username} left room {room}")

@socketio.on('message')
def handle_message(data):
    room = session.get('room')
    username = session.get('username')
    
    if room not in rooms:
        return
    
    message_content = {
        "name": username,
        "message": data["message"]
    }
    
    # Store the message in room history
    rooms[room]["messages"].append(message_content)
    # Limit message history
    if len(rooms[room]["messages"]) > 100:
        rooms[room]["messages"] = rooms[room]["messages"][-100:]
    
    # Send the message to room
    send(message_content, to=room)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)