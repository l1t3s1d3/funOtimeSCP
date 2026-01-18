from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Use data directory if it exists (Docker), otherwise use current directory
DATA_DIR = '/app/data' if os.path.exists('/app/data') else '.'
DATABASE = os.path.join(DATA_DIR, 'workouts.db')

def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with the workouts table"""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            workout TEXT NOT NULL,
            exercise TEXT NOT NULL,
            weight REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/workouts', methods=['GET'])
def get_workouts():
    """Get all workouts"""
    conn = get_db_connection()
    workouts = conn.execute('SELECT * FROM workouts ORDER BY date DESC, created_at DESC').fetchall()
    conn.close()

    return jsonify([dict(row) for row in workouts])

@app.route('/api/workouts', methods=['POST'])
def add_workout():
    """Add a new workout"""
    data = request.get_json()

    # Validate required fields
    required_fields = ['date', 'workout', 'exercise', 'weight']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400

    try:
        # Validate date format
        datetime.strptime(data['date'], '%Y-%m-%d')

        # Validate weight is a number
        weight = float(data['weight'])

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO workouts (date, workout, exercise, weight) VALUES (?, ?, ?, ?)',
            (data['date'], data['workout'], data['exercise'], weight)
        )
        conn.commit()
        conn.close()

        return jsonify({'message': 'Workout added successfully'}), 201
    except ValueError as e:
        return jsonify({'error': 'Invalid data format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/workouts/<int:workout_id>', methods=['DELETE'])
def delete_workout(workout_id):
    """Delete a workout"""
    conn = get_db_connection()
    conn.execute('DELETE FROM workouts WHERE id = ?', (workout_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Workout deleted successfully'}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
