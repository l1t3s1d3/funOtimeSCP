# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create directories with proper permissions
RUN mkdir -p /app/data /app/uploads && \
    chmod -R 755 /app/data /app/uploads

# Expose port 5000
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data

# Run the application
CMD ["python", "app.py"]
