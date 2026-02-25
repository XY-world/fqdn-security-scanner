# FQDN Security Scanner

A comprehensive security scanning tool for Fully Qualified Domain Names (FQDNs). 

## Features

- **DNS Security Analysis**: DNSSEC validation, DNS record enumeration
- **SSL/TLS Certificate Analysis**: Certificate chain validation, expiration checks, cipher suite analysis
- **HTTP Security Headers**: Check for HSTS, CSP, X-Frame-Options, etc.
- **Port Scanning**: Common ports and service detection
- **Subdomain Enumeration**: Discover subdomains via DNS
- **Vulnerability Detection**: Known CVE checks, outdated software detection
- **Report Generation**: JSON, Markdown, and HTML reports

## Installation

```bash
# Clone the repository
git clone https://github.com/XY-world/fqdn-security-scanner.git
cd fqdn-security-scanner

# Install dependencies
pip install -r requirements.txt

# Or use the scanner directly
./scanner.py example.com
```

## Usage

```bash
# Basic scan
python scanner.py example.com

# Full scan with all modules
python scanner.py example.com --full

# Specific modules only
python scanner.py example.com --modules dns,ssl,headers

# Output to file
python scanner.py example.com --output report.json --format json
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

## License

MIT License
