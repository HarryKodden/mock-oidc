FROM python:3.11-slim

WORKDIR /app

# Install required packages including curl for health checks
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements early so pip can install them during image build
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

# Copy the application package
COPY app/ ./app

# Expose port 8888
EXPOSE 8888

# Run the server as module
CMD ["python", "-m", "app.provider"]
