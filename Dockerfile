FROM python:3.11-slim

LABEL maintainer="Ruby570bocadito"
LABEL description="Wormy ML Network Worm v3.0 - ML-Driven Autonomous Network Propagation Platform"

WORKDIR /opt/wormy

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p logs reports saved/rl_agent ml_models/saved wordlists

# Expose dashboard ports
EXPOSE 5000 5001 8443

# Default command
CMD ["python3", "worm_core.py", "--interactive", "--profile", "audit"]
