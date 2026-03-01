# Security Policy

## Supported Versions

The Email Security Pipeline project is currently in active development. Security updates are provided for the following versions:

| Version | Supported          | Python Requirement |
| ------- | ------------------ | ------------------ |
| 1.0.x   | :white_check_mark: | 3.11+              |
| < 1.0   | :x:                | -                  |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in the Email Security Pipeline, please report it responsibly.

### How to Report

**For security vulnerabilities, please use private reporting to prevent exploitation before a fix is available:**

1. **GitHub Security Advisories (Recommended)**: Report privately via [Security Advisories](https://github.com/abhimehro/email-security-pipeline/security/advisories/new)
2. **Alternative - Public Issue**: If Security Advisories are unavailable, create a new issue in the [Issues tab](https://github.com/abhimehro/email-security-pipeline/issues) with the label `security` (only for low-severity issues that don't risk immediate exploitation)

**Include Details**: Please provide:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested remediation (if any)

### What to Expect

- **Initial Response**: We aim to acknowledge security reports within 48 hours
- **Status Updates**: You can expect regular updates as we investigate and work on a fix
- **Resolution Timeline**:
  - Critical vulnerabilities: Patched within 7 days
  - High severity: Patched within 14 days
  - Medium/Low severity: Addressed in the next release cycle
- **Credit**: Security researchers will be credited in the release notes (unless anonymity is requested)

### Security Best Practices

When deploying this pipeline:
- **Never commit credentials**: Use environment variables (`.env` file) and restrict permissions (`chmod 600 .env`). The `.env` file is already protected in `.gitignore` to prevent accidental commits.
- **Keep dependencies updated**: Regularly update Python packages to address known vulnerabilities
- **Use App Passwords**: For Gmail/Outlook integration, use app-specific passwords, not your primary account password
- **Docker Security**: The provided Docker configuration includes security best practices (non-root user, read-only filesystem, resource limits)
- **Rate Limiting**: The pipeline includes built-in rate limiting to prevent API abuse

For more information on securing your deployment, see [ENV_SETUP.md](ENV_SETUP.md) and [QUICKSTART.md](QUICKSTART.md).
