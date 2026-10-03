# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :x:                |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send details to **Site@hotmail.com** with subject line `[SECURITY] QACyberWatch Vulnerability Report`
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix & Disclosure**: Coordinated with reporter, typically within 30 days

### Scope

In scope:
- Authentication and authorization bypasses
- Injection vulnerabilities (SQL, command, template)
- Cross-site scripting (XSS) in the web dashboard
- Sensitive data exposure in API responses
- Configuration vulnerabilities leading to data leaks
- Dependencies with known CVEs

Out of scope:
- Denial of service attacks
- Social engineering
- Issues in third-party services (CertStream, VirusTotal, etc..)
- Vulnerabilities requiring physical access

### Responsible Disclosure

We follow coordinated vulnerability disclosure. We ask that you:
- Allow reasonable time for a fix before public disclosure
- Do not access, modify, or delete data beyond what's needed to demonstrate the issue
- Act in good faith to avoid privacy violations and data destruction

### Recognition

We acknowledge security researchers who report valid vulnerabilities in our CHANGELOG and (with permission) in the project README.

## Security Best Practices for Deployment

- Change default `secret_key` in `config.yaml`
- Use environment variables for API keys and credentials
- Deploy behind a reverse proxy (nginx/Caddy) with TLS
- Restrict API access with firewall rules
- Regularly update dependencies (`dependabot` is configured)
- Review logs in `data/` directory for anomalies
