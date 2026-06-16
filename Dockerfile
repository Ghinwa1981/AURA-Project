# Use the official Python 3.11 slim image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Set environment variables for production python container environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Install dependencies first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy codebase components into the container workspace
COPY main.py .
COPY services/ ./services/
COPY templates/ ./templates/

# Expose the standard Cloud Run port
EXPOSE 8080

# Run uvicorn dynamically bound to the environment-supplied port (defaulting to 8080)
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
