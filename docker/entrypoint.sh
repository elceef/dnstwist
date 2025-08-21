#!/bin/bash
set -e

# Create SSL directory if it doesn't exist
mkdir -p /app/ssl

# Generate SSL certificates if they don't exist or if we're running as root initially
if [ ! -f "/app/ssl/cert.pem" ] || [ ! -f "/app/ssl/key.pem" ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout /app/ssl/key.pem -out /app/ssl/cert.pem -days 365 -nodes \
        -subj "/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy/CN=dnstwist-internal"
fi

# Ensure proper ownership and permissions
chown -R dnstwist:dnstwist /app/ssl
chmod 600 /app/ssl/key.pem
chmod 644 /app/ssl/cert.pem

# Switch to dnstwist user and execute the original command
exec gosu dnstwist "$@"