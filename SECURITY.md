# Security Policy

## Sensitive Data Handling

Stealthix is a database injection detection toolkit that handles sensitive data. This document outlines security best practices for contributors and users.

### Environment Variables and Secrets

Stealthix uses environment variables for API keys and sensitive configuration:

- Keep credentials in environment variables or an operating-system credential store.
- Do not add real API keys, tokens, passwords, certificates, or target data to this repository.
- Use `.env.example` as the documentation surface for supported variable names; it contains placeholders only.

**Never commit these values to version control.** Use the `.env` file locally (which is gitignored) or set them as environment variables.

### What's Excluded from Git

The following sensitive data types are automatically excluded via `.gitignore`:

1. **Credentials & Keys**
   - Private keys (*.pem, *.key, id_rsa, etc.)
   - Certificates (*.crt, *.cer, *.p12, *.pfx)
   - Keystores (*.jks, *.keystore)
   - Environment files (.env, .env.*)
   - API key files (secrets.json, credentials.json)

2. **Database & Test Artifacts**
   - Database files (*.db, *.sqlite)
   - Test results and reports
   - Evidence directories (evidence/, artifacts/, outputs/)

3. **Build & Runtime Artifacts**
   - Python bytecode (__pycache__/, *.pyc)
   - Rust build artifacts (target/)
   - Virtual environments (venv/, .venv/)

### Security Scanning

This repository uses:
- **Bandit**: Python security linter (configured in `bandit.yaml`)
- **pip-audit**: Dependency vulnerability scanner
- **cargo-deny**: Rust dependency security linter

Run security checks before committing:
```bash
bandit -r stealthix/ stealthix_headless_cli/
pip-audit
cargo deny check
```

### Reporting Security Issues

If you discover a security vulnerability in Stealthix, please report it privately:
- Do not open a public GitHub issue
- Contact the maintainers directly through GitHub Security Advisories
- Provide detailed information about the vulnerability

Until a versioned release is published, only the latest `main` branch is supported. Reports, captures, extracted data, and generated evidence may contain sensitive target information; redact them before sharing and store them outside the repository.

### Data Privacy

Stealthix is designed for database injection detection and security testing. Users must:
- Obtain proper authorization before testing databases
- Handle extracted data according to applicable laws and regulations
- Secure test outputs and evidence appropriately
- Follow responsible disclosure practices

## License

Stealthix is licensed under GPL-3.0-or-later. See LICENSE file for details.
