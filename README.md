# Workout Tracker

A simple and elegant web application to track your workout data. Built with Flask (Python) backend and a responsive HTML/CSS/JavaScript frontend, fully containerized with Docker.

## Features

- Add workout entries with date, workout type, exercise name, and weight
- View workout history in a clean, organized interface
- Delete workouts you no longer need
- Persistent storage using SQLite database
- Fully containerized for easy deployment
- Responsive design that works on desktop and mobile

## Tech Stack

- **Backend**: Flask (Python 3.11)
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Database**: SQLite
- **Containerization**: Docker & Docker Compose

## Prerequisites

- Docker and Docker Compose installed on your system

## Quick Start

### Using Docker Compose (Recommended)

1. Clone this repository or download the files

2. Run the application:
   ```bash
   docker-compose up -d
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

4. Start tracking your workouts!

### Using Docker

Build the image:
```bash
docker build -t workout-tracker .
```

Run the container:
```bash
docker run -d -p 5000:5000 -v workout-data:/app/data workout-tracker
```

### Running Locally (Without Docker)

1. Install Python 3.11 or higher

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

1. **Add a Workout**:
   - Select the date
   - Enter the workout name (e.g., "Chest Day", "Leg Day")
   - Enter the exercise (e.g., "Bench Press", "Squats")
   - Enter the weight in pounds
   - Click "Add Workout"

2. **View Workouts**:
   - All workouts are displayed on the right side
   - Most recent workouts appear at the top

3. **Delete a Workout**:
   - Click the "Delete" button on any workout card
   - Confirm the deletion

## API Endpoints

- `GET /api/workouts` - Retrieve all workouts
- `POST /api/workouts` - Add a new workout
- `DELETE /api/workouts/<id>` - Delete a specific workout

## Data Persistence

The application uses SQLite for data storage. When running with Docker Compose, workout data is persisted in a Docker volume named `workout-data`, ensuring your data survives container restarts.

## Stopping the Application

### Docker Compose
```bash
docker-compose down
```

To remove the data volume as well:
```bash
docker-compose down -v
```

## Project Structure

```
.
├── app.py                 # Flask backend application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker image configuration
├── docker-compose.yml    # Docker Compose configuration
├── templates/
│   └── index.html        # Main HTML page
├── static/
│   ├── css/
│   │   └── style.css     # Styles
│   └── js/
│       └── app.js        # Frontend JavaScript
└── README.md             # This file
```

## License

This project is open source and available for personal use.
