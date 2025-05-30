﻿# Connect Chat

A real-time chat application built with Flask, Socket.IO, and MongoDB.

## Features

- **User Authentication**: Complete signup, login, and email verification system
- **Real-time Messaging**: Instant message delivery using WebSockets
- **Room System**: Create or join chat rooms with unique codes
- **Distinctive User Colors**: Users get unique colors for better visual distinction
- **Mobile Responsive**: Works on desktop and mobile devices

## Tech Stack

- **Backend**: Flask, Flask-SocketIO
- **Database**: MongoDB
- **Authentication**: Flask-Bcrypt, Email OTP verification
- **Frontend**: HTML, CSS, JavaScript

## Screenshots

### Login Page
![Login Page](Visualizations/Login%20Page.png)

### Joining Room
![Joining Room](Visualizations/Joining%20Room.png)

### Chat Room
![Chat Room](Visualizations/Chat%20Room.png)

## Setup and Installation

1. Clone the repository
   ```
   git clone https://github.com/akshayamin62/Real-Time-Chat-App
   cd connect-chat
   ```

2. Install dependencies
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables
   Create a `.env` file in the root directory with:
   ```
   EMAIL_ADDRESS=your_email@gmail.com
   EMAIL_PASSWORD=your_app_password
   ```
   Note: For Gmail, you'll need to use an App Password.

4. Install and run MongoDB locally
   - [MongoDB Installation Guide](https://docs.mongodb.com/manual/installation/)

5. Run the application
   ```
   python app.py
   ```

6. Open your browser and go to `http://localhost:5000`

## Usage

1. Sign up with your email address
2. Verify your email with the OTP sent
3. Log in to your account
4. Create a new chat room or join an existing one with a code
5. Start chatting!

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

