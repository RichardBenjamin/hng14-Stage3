# Start from the official Python 3.11 slim image
# "slim" means it has Python but not a lot of extra stuff
# keeping the image size small
FROM python:3.11-slim

# Install iptables at the system level
# This is the tool your detector uses to block IPs
# apt-get is the package manager for Debian/Ubuntu based images
RUN apt-get update && apt-get install -y \
    iptables \
    && rm -rf /var/lib/apt/lists/*
# The last line cleans up the package cache
# so it does not bloat the image size

# Set the working directory inside the container
# All subsequent commands run from this path
# All copied files land here
WORKDIR /app

# Copy requirements.txt first — before the rest of your code
# This is intentional. Docker caches each step.
# If you copy everything at once and change one .py file,
# Docker rebuilds from scratch including reinstalling packages.
# Copying requirements.txt separately means pip install
# only reruns when requirements.txt actually changes.
COPY requirements.txt .

# Install your Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
# --no-cache-dir keeps the image size smaller

# Now copy the rest of your detector files
COPY . .

# Create the directory where your audit log will be written
# This matches the path in config.yaml
RUN mkdir -p /var/log/detector

# When the container starts, run main.py
CMD ["python", "main.py"]
