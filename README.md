# FQDN Security Scanner

A comprehensive security scanning tool for Fully Qualified Domain Names (FQDNs). 

## Features

- **DNS Security Analysis**: DNSSEC validation, DNS record enumeration, SPF/DKIM/DMARC
- **SSL/TLS Certificate Analysis**: Certificate chain validation, expiration checks, cipher suite analysis
- **HTTP Security Headers**: Check for HSTS, CSP, X-Frame-Options, etc.
- **Port Scanning**: Common ports and service detection
- **Subdomain Enumeration**: Discover subdomains via DNS
- **Vulnerability Detection**: Known CVE checks, outdated software detection
- **Report Generation**: JSON, Markdown, and HTML reports
- **Web UI**: Modern Vue.js + Tailwind CSS interface

## Installation

```bash
# Clone the repository
git clone https://github.com/XY-world/fqdn-security-scanner.git
cd fqdn-security-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
# Basic scan
python scanner.py example.com

# Full scan with all modules
python scanner.py example.com --full

# Specific modules only
python scanner.py example.com --modules dns,ssl,headers

# Output to file
python scanner.py example.com --output report.json --format json

# Markdown report
python scanner.py example.com -f md -o report.md
```

### Web UI

```bash
# Start the web server
python web/app.py

# Or use gunicorn for production
gunicorn -w 4 -b 0.0.0.0:5000 web.app:app
```

Then open http://localhost:5000 in your browser.

## API

The web interface exposes a REST API:

### Start Scan
```bash
POST /api/scan
Content-Type: application/json

{
  "target": "example.com",
  "modules": ["dns", "ssl", "headers", "ports", "subdomains", "vulns"],
  "timeout": 30
}
```

### Get Scan Status
```bash
GET /api/scan/{scan_id}
```

### Get Report
```bash
GET /api/scan/{scan_id}/report?format=json|md|html
```

## Modules

| Module | Description |
|--------|-------------|
| `dns` | DNS records, DNSSEC, SPF/DKIM/DMARC |
| `ssl` | TLS certificates, cipher suites, protocols |
| `headers` | HTTP security headers analysis |
| `ports` | Common port scanning |
| `subdomains` | Subdomain enumeration |
| `vulns` | Known vulnerability checks |

## Output Example

```json
{
  "target": "example.com",
  "scan_time": "2026-02-25T04:10:00Z",
  "risk_score": 35,
  "findings": [
    {
      "module": "headers",
      "severity": "medium",
      "title": "Missing Content-Security-Policy",
      "description": "CSP header not set"
    }
  ]
}
```

## Deployment

### Systemd Service

```bash
# Copy service file
sudo cp fqdn-scanner.service /etc/systemd/system/

# Enable and start
sudo systemctl enable fqdn-scanner
sudo systemctl start fqdn-scanner
```

### Nginx Reverse Proxy

```nginx
location /scanner/ {
    proxy_pass http://127.0.0.1:5000/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## License

MIT License
