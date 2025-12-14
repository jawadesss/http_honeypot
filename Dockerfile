# Use official Python slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create persistent data directories
RUN mkdir -p /data /assets

# Expose port
EXPOSE 80

# Use a non-root user for security
RUN useradd -m honeypotuser
USER honeypotuser

# Run the app
CMD ["python", "app.py"]
