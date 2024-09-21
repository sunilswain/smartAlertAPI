from flask import Flask, request, jsonify
import sqlite3
import hashlib
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Database initialization function
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Create users table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL UNIQUE,
                  password TEXT NOT NULL)''')

    # Create events table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_type TEXT,
                  latitude TEXT,
                  longitude TEXT,
                  photo TEXT,
                  comment TEXT,
                  user_id INTEGER,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()

# Hashing passwords for security
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# API endpoint for registration
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    hashed_password = hash_password(password)

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 409
    finally:
        conn.close()

    return jsonify({'message': 'User registered successfully'}), 201

# API endpoint for login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    hashed_password = hash_password(password)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
    user = c.fetchone()
    conn.close()

    if user:
        return jsonify({
            'message': 'Login successful',
            'email': email,
            'userId': user[0]
        }), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/events/create', methods=['POST'])
def send_event():
    data = request.json
    event_type = data.get('type')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    photo = data.get('photo')
    comment = data.get('comment')
    user_id = data.get('user_id')

    # Validate inputs
    if not all([event_type, latitude, longitude, user_id]):
        return jsonify({'error': 'Event type, latitude, longitude, and user ID are required'}), 400

    # Insert the event into the events table
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO events (event_type, latitude, longitude, photo, comment, user_id) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
              (event_type, latitude, longitude, photo, comment, user_id))
    event_id = c.fetchone()[0]
    conn.commit()
    conn.close()

    return jsonify({
        'message': 'Event sent successfully',
        'event': {
            'id': event_id,
            'type': event_type,
            'latitude': latitude,
            'longitude': longitude,
            'photo': photo,
            'comment': comment,
            'user_id': user_id
        }
    }), 201

# API endpoint for getting user event statistics
@app.route('/events/stats', methods=['GET'])
def get_event_statistics():
    user_id = request.args.get('id')

    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute("SELECT event_type, COUNT(*) FROM events WHERE user_id = ? GROUP BY event_type", (user_id,))
    rows = c.fetchall()
    statistics = {
        'earthquakeEventsNum': 0,
        'fireEventsNum': 0,
        'floodEventsNum': 0,
    }

    for event_type, count in rows:
        if event_type == 'Earthquake':
            statistics['earthquakeEventsNum'] += count
        elif event_type == 'Fire':
            statistics['fireEventsNum'] += count
        elif event_type == 'Flood':
            statistics['floodEventsNum'] += count

    conn.close()

    return jsonify(statistics), 200

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)
