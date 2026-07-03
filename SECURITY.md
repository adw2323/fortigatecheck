# Security Policy

**Tags:** #fortigatecheck #security

---

## Reporting Vulnerabilities

If you discover a security vulnerability in fortigatecheck, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue
2. Email: [security contact]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What We Promise

- Acknowledge receipt within 48 hours
- Provide a timeline for fix
- Credit you in the changelog (unless you prefer anonymity)
- Not pursue legal action for good-faith security research

### Scope

In-scope:
- Code execution vulnerabilities
- Path traversal
- Injection attacks
- Denial of service
- Information disclosure

Out-of-scope:
- Social engineering
- Physical attacks
- Issues in dependencies (report to upstream)

---

## Security Considerations for Users

### Input Validation

fortigatecheck processes FortiGate config files. While we validate input:
- Only process configs from trusted sources
- Be aware that config files may contain sensitive data (IPs, hostnames, keys)
- Use `--quiet` mode when piping to logs

### Output Security

- Reports may contain config details
- Store reports securely
- Redact sensitive info before sharing

### Dependencies

We regularly update dependencies and monitor for vulnerabilities.
Run `pip audit` to check for known issues.
