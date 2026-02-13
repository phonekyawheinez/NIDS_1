# Use a lightweight Python image
FROM python:latest

# Install Java (Required for PySpark)
RUN apt-get update && \
    apt-get install -y openjdk-17-jre-headless procps && \
    apt-get clean

# Set Environment Variables for Spark
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PYSPARK_PYTHON=python3

WORKDIR /app

# 1. Copy the requirements first (for better caching)
COPY scripts/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Copy the necessary folders into the image
COPY scripts/ ./scripts/
COPY saved_models/ ./saved_models/

# 3. Set the default command to run your processor
# Note: We use the path relative to /app
CMD ["python", "scripts/realtime_processor.py"]