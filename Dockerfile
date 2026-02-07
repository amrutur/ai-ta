# Dockerfile for ADK agent system
FROM python:3.13-slim-bookworm


WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your agent code
COPY . .

# Set environment variables
ENV PORT=8080
ENV GOOGLE_CLOUD_PROJECT=ai-ta-486602
ENV PRODUCTION=1

# Run the application
CMD ["python", "src/api_server.py"]