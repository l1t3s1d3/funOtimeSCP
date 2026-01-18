// Set today's date as default
document.getElementById('date').valueAsDate = new Date();

// Load workouts on page load
document.addEventListener('DOMContentLoaded', loadWorkouts);

// Handle form submission
document.getElementById('workoutForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = {
        date: document.getElementById('date').value,
        workout: document.getElementById('workout').value,
        exercise: document.getElementById('exercise').value,
        weight: parseFloat(document.getElementById('weight').value)
    };

    try {
        const response = await fetch('/api/workouts', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        const data = await response.json();

        if (response.ok) {
            showMessage('Workout added successfully!', 'success');
            document.getElementById('workoutForm').reset();
            document.getElementById('date').valueAsDate = new Date();
            loadWorkouts();
        } else {
            showMessage(data.error || 'Failed to add workout', 'error');
        }
    } catch (error) {
        showMessage('Error connecting to server', 'error');
        console.error('Error:', error);
    }
});

// Load and display workouts
async function loadWorkouts() {
    const workoutList = document.getElementById('workoutList');
    workoutList.innerHTML = '<p class="loading">Loading workouts...</p>';

    try {
        const response = await fetch('/api/workouts');
        const workouts = await response.json();

        if (workouts.length === 0) {
            workoutList.innerHTML = '<p class="empty-state">No workouts recorded yet. Add your first workout!</p>';
            return;
        }

        workoutList.innerHTML = workouts.map(workout => `
            <div class="workout-card">
                <div class="workout-info">
                    <div class="workout-date">${formatDate(workout.date)}</div>
                    <div class="workout-name">${workout.workout}</div>
                    <div class="workout-details">
                        ${workout.exercise} - <span class="workout-weight">${workout.weight} lbs</span>
                    </div>
                </div>
                <button class="btn btn-danger" onclick="deleteWorkout(${workout.id})">Delete</button>
            </div>
        `).join('');
    } catch (error) {
        workoutList.innerHTML = '<p class="error">Error loading workouts</p>';
        console.error('Error:', error);
    }
}

// Delete a workout
async function deleteWorkout(id) {
    if (!confirm('Are you sure you want to delete this workout?')) {
        return;
    }

    try {
        const response = await fetch(`/api/workouts/${id}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showMessage('Workout deleted successfully!', 'success');
            loadWorkouts();
        } else {
            showMessage('Failed to delete workout', 'error');
        }
    } catch (error) {
        showMessage('Error connecting to server', 'error');
        console.error('Error:', error);
    }
}

// Show message to user
function showMessage(text, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = text;
    messageDiv.className = `message ${type}`;

    setTimeout(() => {
        messageDiv.className = 'message';
    }, 3000);
}

// Format date for display
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString + 'T00:00:00').toLocaleDateString('en-US', options);
}
