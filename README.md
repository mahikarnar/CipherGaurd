# Cipher Gaurd

A comprehensive password analysis tool built with Python, Gradio, and machine learning techniques. This tool provides real-time password strength assessment, breach detection, and security recommendations.

## Features

### Core Analysis
- **Advanced Strength Scoring**: 0-100 scale based on multiple factors
- **Entropy Calculation**: Mathematical measure of password randomness
- **Character Variety Analysis**: Checks for uppercase, lowercase, numbers, symbols
- **Pattern Detection**: Identifies common weak patterns and sequences
- **Length Analysis**: Optimal length recommendations

### Security Features
- **Breach Detection**: Integration with Have I Been Pwned API using k-anonymity
- **Rate Limiting**: Prevents abuse with configurable limits
- **Secure Data Handling**: Passwords never stored or logged
- **HTTPS Support**: SSL/TLS encryption for secure transmission

### User Experience
- **Visual Strength Meter**: Dynamic color-coded strength indicators
- **Dark Mode Interface**: Modern, eye-friendly design
- **Real-time Analysis**: Instant feedback as you type
- **Detailed Recommendations**: Specific advice for password improvement
- **Multiple Examples**: Test cases for different password types

### Deployment Options
- **Docker Support**: Containerized deployment
- **Kubernetes Ready**: Scalable container orchestration
- **Cloud Platform Integration**: AWS, GCP, Azure deployment scripts
- **Django Integration**: API endpoints for web applications
- **Reverse Proxy**: Nginx configuration with SSL termination

## Quick Start

### Prerequisites
- Python 3.8+
- pip package manager
- Docker (for containerized deployment)

### Local Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/CipherGaurd.git
   cd CipherGaurd
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the interface**
   - Open your browser to `http://localhost:7860`

### Docker Deployment

1. **Build the image**
   ```bash
   docker build -t CipherGaurd .
   ```

2. **Run the container**
   ```bash
   docker run -p 7860:7860 CipherGaurd
   ```

3. **Or use Docker Compose**
   ```bash
   docker-compose up -d
   ```

## API Documentation

### Analyze Password Endpoint

**POST** `/api/CipherGaurd/`

**Request Body:**
```json
{
  "password": "your_password_here"
}
```

**Response:**
```json
{
  "Overall Strength": "Very Strong",
  "Score": "89/100",
  "Length Analysis": "16 characters",
  "Character Variety": "4/4 types: lowercase, UPPERCASE, numbers, symbols",
  "Entropy": "68.4 bits",
  "Breach Status": "Not found in known breaches",
  "Security Issues": "No common patterns detected",
  "Recommendations": "Great! This is a strong password.",
  "Strength Meter": "[████████████████████] 89/100"
}
```

### Rate Limiting
- **Limit**: 20 requests per minute per IP
- **Response**: 429 Too Many Requests when exceeded

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GRADIO_SERVER_PORT` | 7860 | Port to run the server |
| `GRADIO_SERVER_NAME` | 127.0.0.1 | Host address |
| `RATE_LIMIT_CALLS` | 20 | Max calls per window |
| `RATE_LIMIT_WINDOW` | 60 | Rate limit window (seconds) |
| `HIBP_TIMEOUT` | 5 | API timeout for breach checking |

### Custom Configuration

```python
# app.py modifications
interface.launch(
    server_port=int(os.getenv('GRADIO_SERVER_PORT', 7860)),
    server_name=os.getenv('GRADIO_SERVER_NAME', '0.0.0.0'),
    auth=('username', 'password'),  # Add authentication
    ssl_keyfile='path/to/key.pem',   # SSL key
    ssl_certfile='path/to/cert.pem'  # SSL certificate
)
```

## Security Considerations

### Data Protection
- **No Password Storage**: Passwords are never saved to disk or logs
- **Memory Clearing**: Sensitive data cleared from memory after analysis
- **k-Anonymity**: Breach checking uses first 5 characters of SHA-1 hash only

### Network Security
- **HTTPS Enforcement**: All communications encrypted
- **HSTS Headers**: Prevent downgrade attacks
- **Rate Limiting**: Prevent brute force and abuse
- **CORS Protection**: Cross-origin request filtering

### Deployment Security
- **Non-root User**: Container runs as unprivileged user
- **Security Headers**: X-Frame-Options, CSP, etc.
- **Input Validation**: Strict input sanitization
- **Error Handling**: No sensitive information in error messages

## Monitoring and Logging

### Health Checks
```bash
curl -f http://localhost:7860/health
```

### Metrics Collection
- Request count and response times
- Rate limiting violations
- API error rates
- System resource usage

### Log Levels
- **INFO**: Normal operations
- **WARN**: Rate limiting, API timeouts
- **ERROR**: System errors, API failures

## Cloud Deployment

### AWS ECS
```bash
# Build and push to ECR
./deploy-aws.sh

# Deploy with CloudFormation
aws cloudformation deploy --template-file aws-template.yaml \
  --stack-name CipherGaurd --capabilities CAPABILITY_IAM
```

### Google Cloud Run
```bash
# Deploy to Cloud Run
./deploy-gcp.sh

# Configure custom domain
gcloud run domain-mappings create --service CipherGaurd \
  --domain your-domain.com
```

### Azure Container Instances
```bash
# Deploy to ACI
./deploy-azure.sh

# Configure custom domain
az network dns record-set cname create -g myResourceGroup \
  -z your-domain.com -n app --cname CipherGaurd.eastus.azurecontainer.io
```

### Kubernetes
```bash
# Deploy to K8s cluster
kubectl apply -f k8s-deployment.yaml

# Expose with ingress
kubectl apply -f k8s-ingress.yaml
```

## Testing

### Unit Tests
```bash
python -m pytest tests/test_Cipher_Gaurd.py -v
```

### Integration Tests
```bash
python -m pytest tests/test_integration.py -v
```

### Load Testing
```bash
# Using Apache Bench
ab -n 1000 -c 10 -p test_password.json -T application/json \
  http://localhost:7860/api/analyze-password/

# Using wrk
wrk -t12 -c400 -d30s --script=post_password.lua http://localhost:7860/
```

## Troubleshooting

### Common Issues

**Issue**: "Rate limit exceeded"
- **Solution**: Wait 60 seconds or increase rate limits in configuration

**Issue**: "HIBP API unavailable"
- **Solution**: Check internet connection and HIBP service status

**Issue**: "Port 7860 already in use"
- **Solution**: Change port in environment variables or stop conflicting process

**Issue**: SSL certificate errors
- **Solution**: Ensure certificate files exist and have correct permissions

### Debug Mode
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Launch with debug
interface.launch(debug=True, show_error=True)
```

