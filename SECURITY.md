# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### Do NOT

- Open a public GitHub issue describing the vulnerability
- Share the vulnerability publicly before it has been fixed
- Exploit the vulnerability further to demonstrate impact

### DO

- Send an email to the repository maintainer
- Include a clear description of the vulnerability
- Include steps to reproduce (if applicable)
- Provide a suggested fix (if you have one)
- Allow reasonable time for the maintainers to respond (up to 90 days)

### What to Report

- Authentication bypass or privilege escalation
- SQL injection or command injection vulnerabilities
- Sensitive data exposure (API keys, tokens, personal data)
- Denial of service vulnerabilities
- Any vulnerability that could compromise user data

## Security Features in This Project

- **Input sanitization** on all user inputs via `utils/validators.py`
- **Rate limiting** to prevent API abuse via `utils/rate_limiter.py`
- **Audit logging** of all queries for accountability
- **Non-root execution** in Docker containers
- **No secrets in code** — all credentials from environment variables
- **Code runner blacklist** prevents dangerous commands
- **Password generator** never logs generated passwords

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅        |
| < 2.0    | ❌        |

## API Key Security

- Never commit API keys to the repository
- Use environment variables exclusively
- Rotate keys every 90 days
- Use minimum-scope permissions for GitHub tokens
- Revoke compromised keys immediately

## Dependencies

This project uses the following Python packages:
- `python-telegram-bot` — Official Telegram Bot API wrapper
- `aiohttp` — Async HTTP client
- `dnspython` — DNS resolution
- `python-whois` — WHOIS lookups
- `Pillow` — Image processing
- `exifread` — EXIF metadata extraction

To report a vulnerability in a dependency, follow that project's security policy.

## Acknowledgments

We appreciate responsible disclosure and will credit security researchers who help improve this project.
