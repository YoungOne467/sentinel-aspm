# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within the SENTINEL platform itself (not the vulnerabilities SENTINEL is designed to find in other applications), please report it **responsibly** by following the steps below.

### Do NOT

- Open a public GitHub issue for security vulnerabilities.
- Post vulnerability details in public forums, Discord, or social media before the fix has been released.

### Do

1. **Email the maintainers directly** with the subject line: `[SECURITY] Vulnerability Report — SENTINEL`.
2. Include the following details in your report:
   - A description of the vulnerability and its potential impact.
   - Steps to reproduce the issue.
   - Affected versions or commits.
   - Any suggested fixes or mitigations (optional but appreciated).
3. Allow a reasonable disclosure period (up to **90 days**) for the team to investigate and patch the vulnerability before public disclosure.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| `main`  | :white_check_mark: |

## Scope

This security policy applies to vulnerabilities found in:

- The SENTINEL backend API (`backend/`)
- The SENTINEL frontend dashboard (`aspm-frontend/`)
- The plugin SDK and governance packages (`packages/`)
- CI/CD pipeline configurations and Docker infrastructure

## Disclaimer

SENTINEL is a security testing tool designed for authorized, ethical vulnerability scanning. Users are solely responsible for ensuring they have proper authorization before scanning any targets. Unauthorized scanning of systems you do not own or have permission to test is illegal and unethical.
