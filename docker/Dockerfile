# DNStwist Web App Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gcc \
    python3-dev \
    libfuzzy-dev \
    libfuzzy2 \
    && rm -rf /var/lib/apt/lists/*

# Clone dnstwist repository and copy webapp files
RUN git clone https://github.com/elceef/dnstwist.git /tmp/dnstwist && \
    cp /tmp/dnstwist/webapp/webapp.py ./ && \
    cp /tmp/dnstwist/webapp/webapp.html ./ && \
    cp /tmp/dnstwist/dnstwist.py ./ && \
    rm -rf /tmp/dnstwist

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask \
    gunicorn \
    idna \
    tld \
    dnspython \
    requests

# Create a non-root user
RUN useradd -m -u 1001 dnstwist
USER dnstwist

# Expose port
EXPOSE 8000

# Set environment variables
ENV HOST=0.0.0.0
ENV PORT=8000
ENV THREADS=10

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Run the webapp
CMD ["gunicorn", "webapp:app", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "10", "--log-level", "info"]