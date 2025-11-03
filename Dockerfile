# Multi-stage Dockerfile for Anomaly Dashboard
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set work directory
WORKDIR /app



# Copy requirements first (for better Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# # Create necessary directories
# RUN mkdir -p /app/templates
# RUN mkdir -p /app/main

# # Copy the HTML template to the templates directory
# RUN cp paste.txt templates/dashboard.html || echo "Warning: paste.txt not found, please ensure dashboard.html is in templates/"



RUN chmod +x /app/entrypoint.sh
# Default command
#CMD ["python3", "main.py"]
ENTRYPOINT ["/app/entrypoint.sh"]