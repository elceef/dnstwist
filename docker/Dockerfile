# DNStwist Web App Dockerfile
FROM 764525110978.dkr.ecr.us-west-2.amazonaws.com/python:3.11-slim-bookworm-arm

WORKDIR /app

# Ensure we're running as root for system package installation
USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gcc \
    python3-dev \
    libfuzzy-dev \
    libfuzzy2 \
    openssl \
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

# Create SSL directory and generate self-signed certificate
RUN mkdir -p /app/ssl && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/ssl/key.pem -out /app/ssl/cert.pem -days 365 -nodes \
    -subj "/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy/CN=dnstwist-internal" && \
    chmod 600 /app/ssl/key.pem && chmod 644 /app/ssl/cert.pem

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
    CMD curl -f -k https://localhost:8000/ || exit 1

# Run the webapp
CMD ["gunicorn", "webapp:app", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "10", "--log-level", "info", "--certfile", "/app/ssl/cert.pem", "--keyfile", "/app/ssl/key.pem"]