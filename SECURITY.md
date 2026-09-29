# Security and deployment boundaries

Scopeglass is for networks you administer or have permission to assess. It records service observations; it does not establish internet exposure, authenticated device identity, or a confirmed vulnerability.

Use the Python backend on loopback or a private interface restricted to your HTTPS proxy. Shared access requires the administrator login and HTTPS configuration described in [deploy/README.md](deploy/README.md). The current release has one full-access account and process-local sign-in throttling; it has no MFA, SSO, or per-user permissions. This is not a hardened public internet search service and has not received an independent security audit.

Keep databases, backup files, and the scanner's host private. JSON exports contain network evidence and annotations. SQLite backups also contain account/session hashes. Reset the passphrase before serving a restored SQLite backup to revoke restored sessions. Keep SQLite on local storage; network filesystems and hard-linked database copies are unsupported. Run one server per database and leave its `.lock` file in place, including after a crash.

## Report a suspected problem

Use the repository's **Security → Report a vulnerability** option if its maintainer has enabled private reporting. If unavailable, ask the maintainer for a private reporting channel without posting exploit details, credentials, database files, or a real network inventory in a public issue. No private-reporting address or hosted repository is provisioned by this source package.

Include the Scopeglass version, operating system, deployment mode, expected/observed behavior, and a minimal reproduction using synthetic loopback data. Avoid testing a suspected issue on systems you do not own.

This candidate does not promise an LTS/support window. Use the latest tested release available from your chosen maintainer; review release notes and keep a consistent pre-upgrade backup.
