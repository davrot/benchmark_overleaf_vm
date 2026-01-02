# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask

# Copy the server script
COPY server.py .

# Expose port
EXPOSE 8000

# Run the server
CMD ["python", "server.py"]
