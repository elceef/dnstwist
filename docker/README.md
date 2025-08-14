# DNStwist Webapp Deployment Guide

## Deployment Steps

### 1. Authenticate with AWS
```bash
# Authenticate via Okta (as per your main README)
okta
```

### 2. Build the Docker Image
```bash
# From the infra repository root
docker build -t dnstwist-webapp:latest docker/dnstwist-webapp/
```

### 3. Create ECR Repository (if it doesn't exist)
```bash
aws ecr create-repository --repository-name dnstwist-webapp --region us-west-2
```

### 4. Get ECR Login Token
```bash
# Get your AWS account ID and login to ECR
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.us-west-2.amazonaws.com
```

### 5. Tag Image for ECR
```bash
docker tag dnstwist-webapp:latest $ACCOUNT_ID.dkr.ecr.us-west-2.amazonaws.com/dnstwist-webapp:latest
```

### 6. Push to ECR
```bash
docker push $ACCOUNT_ID.dkr.ecr.us-west-2.amazonaws.com/dnstwist-webapp:latest
```

### 7. Deploy Infrastructure
```bash
# Navigate to CDK directory
cd cdk/

# Set environment for deployment
export AWS_ENV=dev-private  # or your target environment

# Build and deploy
npm run build
npm run cdk -- deploy "*dnstwist*"
```

## What This Image Contains

- **Frontend**: Complete HTML/JavaScript web interface (`webapp.html`)
- **Backend**: Flask API server (`webapp.py`) with dnstwist scanning engine
- **Web Server**: Gunicorn serving both frontend and API on port 8000
- **Dependencies**: All required Python packages for domain scanning

## Testing Locally

```bash
# Run locally for testing
docker run -d -p 8080:8000 --name dnstwist-webapp-test dnstwist-webapp:latest

# Access the web UI
open http://localhost:8080

# Clean up
docker stop dnstwist-webapp-test && docker rm dnstwist-webapp-test
```
