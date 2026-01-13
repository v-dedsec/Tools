# 🛡️ Defensive Security Research Toolkit

A collection of **read-only** security assessment tools designed for **ethical security research** and **defensive analysis**. All tools follow strict safety constraints to prevent any form of exploitation or unauthorized access.

## 🚨 Safety First Philosophy

All tools in this toolkit are built with **defensive security research** principles:
- ✅ **Read-only operations** - No data modification or injection
- ✅ **Immediate stop on detection** - No probing beyond initial findings
- ✅ **Size limits** - Maximum 1KB response analysis
- ✅ **No authentication attempts** - Zero credential testing
- ✅ **Header-only analysis** - No content parsing or extraction
- ✅ **Rate limiting** - Respectful scanning with delays

---

## 📋 Tool Overview

| Tool | Purpose | Safety Level | Detection Method |
|------|---------|--------------|------------------|
| **Admin Panel Detector** | Find admin interfaces | 🔒 Read-only | HEAD/GET requests |
| **Spring Boot Scanner** | Detect exposed actuators | 🔒 Read-only | HEAD requests only |
| **Sensitive File Scanner** | Find exposed config files | 🔒 Ultra-safe | HEAD requests, immediate stop |
| **API Auth Checker** | Test authorization bypass | 🔒 Non-intrusive | No auth vs invalid token |
| **Cloud Exposure Detector** | Find public Grafana/Kibana | 🔒 Passive | HEAD requests, no queries |
| **HTTP Header Analyzer** | Security header assessment | 🔒 Header-only | No payload injection |

---

## 🛠️ Installation & Setup

```bash
# Clone the repository
git clone https://github.com/v-dedsec/Tools.git

cd defensive-security-toolkit

# Install dependencies
pip install -r requirements.txt

# Make tools executable
chmod +x *.py
```

🔧 Tool Details & Usage

1. 🎯 Admin Panel Detection Tool

Purpose: Ethically detect admin panel locations without attempting access

Key Features:

a.Only HEAD/GET requests (no POST/form submissions)
b.Content limiting: 2000 characters max
c.User-agent rotation to avoid detection
d.SSL certificate verification
e.Configurable rate limiting
````
Usage:
# Basic scan
python admin_detector.py https://example.com

# Multiple targets with custom delay
python admin_detector.py https://site1.com https://site2.com --delay 2.0

# Generate JSON report
python admin_detector.py https://target.com --output report.json

# Rate limited scanning (0.5 req/sec)
python admin_detector.py https://target.com --rate-limit 0.5
````
Output Example:

🔍 ADMIN PANEL DETECTION REPORT
=====================================
URL: https://example.com/admin
Confidence: 85%
Access Level: protected
Risk: medium
Indicators: Admin keywords found, redirected to login


2. 🔍 Spring Boot Endpoint Detector

Purpose: Detect exposed Spring Boot actuators and management endpoints

Safety Features:

a.HEAD requests only for sensitive endpoints
b.1KB response size limit
c.5-second timeout protection
d.Stops at 401/403 responses
e.No response body storage

````
Usage:
# Single target
python3 actuator_scanner.py https://example.com

# Multiple targets
python3 actuator_scanner.py https://app1.com https://app2.com

# Custom timeout with verbose mode
python3 actuator_scanner.py https://example.com --timeout 10 --max-size 2048 -v
````
Risk Classifications:

🔒 Secure: No exposed endpoints
⚠️ Potentially Exposed: Sensitive endpoints accessible
❓ Inconclusive: Spring Boot not detected
👁️ Monitor: Safe endpoints exposed



3. 🔒 Defensive Sensitive File Scanner

Purpose: Detect publicly accessible sensitive configuration files

Ultra-Safe Design:

a.HEAD requests ONLY (never downloads files)
b.Immediate stop when sensitive files detected
c.1KB maximum response size
d.No content parsing or analysis
e.Header-only risk assessment

Target Files: .env, .git/config, backup.zip, config.yml, database.sql
````
Usage:

# Basic scan
python3 sensitive_scanner.py https://example.com

# Custom timeout
python3 sensitive_scanner.py https://api.example.com --timeout 15

# Save report to file
python3 sensitive_scanner.py https://example.com --output scan_report.txt
````
Output Format:

🚨 CRITICAL: .env file exposed at https://example.com/.env
Status: 200 OK
Content-Type: text/plain
Risk: CRITICAL - Environment configuration exposed
⚠️  Scanner stopped - Critical finding detected


4. 🔐 API Authorization Detection Tool

Purpose: Test for API authorization bypass vulnerabilities

Non-Intrusive Design:

a.Only tests: No auth header vs Invalid token
b.No parameter fuzzing or manipulation
c.No response data extraction
d.Stops immediately on auth bypass confirmation
````
Usage:
# Test single endpoint
python api_auth_scanner.py -u https://api.example.com/users

# Test multiple endpoints
python api_auth_scanner.py -u https://api.example.com/users https://api.example.com/posts -m GET POST

# Save results to JSON
python api_auth_scanner.py -u https://api.example.com/admin -o results.json
````
Severity Ratings:

🚨 CRITICAL: 200 response without auth (full access)
⚠️ HIGH: 201/202 response without auth (resource creation)
⚡ MEDIUM: Redirects without auth
🔍 LOW: 400/404 responses (info disclosure)
✅ SECURE: 401/403 responses (proper auth)


5. ☁️ Public Cloud Exposure Detector

Purpose: Detect publicly exposed Grafana, Prometheus, and Kibana instances

Detection Capabilities:

a.HEAD requests only (GET only if HEAD blocked)
b.Service identification via headers/titles/content patterns
c.Athentication requirement detection
d.Multi-threaded concurrent scanning
e.No data queries, searches, or metric access
````
Usage:
# Single target
python cloud_detector.py https://grafana.example.com

# Multiple targets
python cloud_detector.py https://grafana.example.com http://prometheus.internal:9090

# Scan from file
python cloud_detector.py -f targets.txt -o json

# Custom workers and timeout
python cloud_detector.py -t 10 -w 20 https://kibana.example.com
````
Risk Classification:
🚨 CRITICAL: No auth required, full access
⚠️ HIGH: Weak auth or default credentials
⚡ MEDIUM: Auth required but publicly accessible
🔍 LOW: Properly secured instance


6. 🔒 HTTP Header Security Analyzer

Purpose: Analyze HTTP security headers for common misconfigurations

Passive Analysis Only:

No payload injection or exploitation
Header-only inspection
OWASP Top 10 mapping
Safe for production use

Key Checks:
Missing CSP (XSS protection)
Missing HSTS (protocol downgrade)
Insecure CORS (wildcard origins)
Cookie security (HttpOnly/Secure flags)
Information disclosure (technology fingerprinting)
````
Usage:
# Basic analysis
python3 security_header_analyzer.py https://example.com

# JSON output with SSL verification
python3 security_header_analyzer.py https://example.com --json --verify-ssl
````
````
# Batch processing script
#!/bin/bash
while read url; do
    echo "Analyzing: $url"
    python3 security_header_analyzer.py "$url" >> security_report.txt
    echo "----------------------------------------" >> security_report.txt
done < urls.txt
````
Sample Output:

================================================================================
HTTP SECURITY HEADER ANALYSIS REPORT
================================================================================
URL: https://example.com
Status Code: 200
Analysis Time: 2024-01-11T12:00:00.000000

[HIGH] SEVERITY FINDINGS:
--------------------------------------------------
Type: Missing Header
Description: Missing Content-Security-Policy (CSP)
OWASP: A03:2021 - Injection
Fix: content-security-policy: default-src 'self'

Type: Cookie Security
Description: Cookie 'session_id' missing HttpOnly
OWASP: A05:2021 - Security Misconfiguration
Fix: Add HttpOnly flag

SECURITY SUMMARY:
------------------------------  
HIGH: 2 findings
MEDIUM: 1 findings


# ⚖️ Legal & Ethical Guidelines

## ✅ Authorized Use Only

Written permission required for scanning any system you don't own
Bug bounty programs with clear scope definitions
Your own systems and infrastructure
Educational purposes in controlled environments

## ❌ Prohibited Activities

Scanning without explicit authorization
Using findings for malicious purposes
Ignoring rate limits or causing service disruption
Attempting to access or exfiltrate data

## 🛡️ Protection Mechanisms

All tools include safety constraints by design
Read-only operations prevent any data modification
Immediate stop on sensitive findings
Rate limiting to avoid service impact

## 📊 Contributing & Support

### Contributing Guidelines
- Safety first: All contributions must maintain read-only principles
- Ethical focus: Tools must be defensive-only
- Documentation: Update README with new features
- Testing: Ensure safety constraints work properly

### Support & Issues
- Security concerns: Report immediately via security email
- Bug reports: Use GitHub issues with detailed information
- Feature requests: Focus on defensive security capabilities

## 📄 License & Disclaimer

MIT License - See LICENSE file for full details
⚠️ **Disclaimer**: These tools are for authorized security research only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse or damage caused by these tools.

## 🏆 Best Practices

- Always get permission before scanning any system
- Start with gentle settings (higher delays, smaller scope)
- Document your findings responsibly and ethically
- Report vulnerabilities through proper channels
- Respect rate limits and scan during off-peak hours
- Use responsibly - these are defensive tools only

## 🔒 Remember: With great scanning power comes great responsibility. Use these tools ethically and legally.


