# Security Policy

## Supported Versions
Security fixes are provided for the **latest released version** only.

## Reporting a Vulnerability
Please **do not** open a public GitHub issue for security vulnerabilities.

### Preferred method (private)
Use GitHub Security Advisories:
- Go to the repository **Security** tab
- Click **Report a vulnerability**
- Provide a clear description and (if possible) reproduction steps

### What to include
- Valerter version and installation method (.deb / static binary / etc.)
- VictoriaLogs version (if relevant)
- Minimal configuration snippet (redact secrets)
- Logs / stack traces (redact secrets)
- Impact assessment (what an attacker could do)

## Disclosure Process
After receiving a report, we aim to:
- Acknowledge receipt within **72 hours**
- Provide an initial assessment within **7 days**
- Coordinate a fix and release, then publish an advisory if appropriate

## Security Notes
- Never include secrets (tokens, SMTP passwords, webhook URLs) in reports.
- If you are unsure whether something is a security issue, report it privately anyway.
