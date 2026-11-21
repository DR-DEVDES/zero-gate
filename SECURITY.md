# Security Policy

Do not publish passwords, session cookies, live access hashes, or exploit
details in a public issue. Contact the repository maintainer privately.

Deployment checklist:
- Use HTTPS.
- Keep PHP updated.
- Keep real password hashes out of version control.
- Use a unique, strong password for every protected deployment.
- Add server-side/IP-based rate limiting for public-facing deployments.
- Restrict filesystem permissions on PHP files and configuration.
