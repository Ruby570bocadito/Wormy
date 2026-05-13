# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.0.x   | Yes       |

## Reporting a Vulnerability

This project is an educational red-team framework for authorized security testing.
If you discover a security vulnerability in the codebase itself (not the attack
capabilities, but the project's own security):

1. Do NOT open a public issue
2. Email: ruby570bocadito@github.com
3. Include "WORMY SECURITY" in the subject line
4. Provide a clear description and proof of concept

## Known Security Considerations

This framework generates offensive payloads that may be flagged by antivirus.
Key built-in risk mitigations:

- A default kill switch code is set and must be changed per engagement
- The `--dry-run` flag simulates without executing real exploits
- Configurable SSL verification via WORMY_SSL_VERIFY env var
- All credentials should be set via environment variables, not config files
- JWT secret must be changed from default in production use
