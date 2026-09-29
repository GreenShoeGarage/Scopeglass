# Changelog

## 1.0.0-rc.1

- Refuse a second process on the same canonical database path before migration or scan recovery; release ownership automatically on exit/crash. Guided setup also refuses a database owned by a running process.
- Reserve the HTTP port before modifying saved state; an occupied port now exits with a concise setup error.
- Wait for in-flight requests, the scheduler, and the active scan to finish saving during graceful shutdown.
- Refuse newer database schemas before startup, config checking, setup, or terminal password reset. Schema remains 9.
- Accept this candidate's JSON exports for restore and keep prior v0.3–v0.9 support.
- Simplify the README around user tasks; add contribution, security, and stable-release gate documentation.
- Add deterministic allowlist-based ZIP packaging with checksums and a clean generated starter config.
- Add six subprocess regression tests, GitHub CI configuration, and a disposable Docker smoke test. Remote CI and live Docker/Caddy/systemd deployment are still pending; this is a release candidate.

## 0.9.0

- Added a single administrator account with salted PBKDF2 hashes, hashed session tokens, cookie sessions, CSRF protection, and sign-in throttling.
- Added sign-in/out, passphrase change, terminal reset, expiry recovery, and a visible access/setup panel.
- Preserved password-free loopback access; require login for non-loopback listeners and HTTPS origins for shared browser access.
- Validate configured Host/Origin boundaries and reject cross-origin writes; ignore forwarded identity/protocol headers.
- Added setup/config-check CLI flows, private file defaults, minimal health checks, and graceful signal handling.
- Added a non-root Docker/Compose package, systemd service, Caddy example, and deployment/upgrade/rollback guide.
- Preserve accounts/sessions during assessment restore and Fresh Start; exclude access tables from JSON exports.
- Added 12 authentication/deployment/upgrade tests and an HTTPS browser workflow; all 51 Python tests and four browser suites passed.

## 0.8.0

- Added validated whole-dataset JSON restore with count previews, typed confirmation, expiring data-bound previews, and paused restored schedules.
- Added automatic integrity-checked SQLite backups before maintenance, transactional rollback, and stale-client dataset identity checks.
- Added manual age-based scan cleanup protecting all retained references, and Fresh Start with browser preferences/draft reset.
- Added full filtered CSV output with quoted fields and spreadsheet-formula text protection.
- Reworked printable reports with a review summary, readable protocol evidence, and next steps; reports and CSV use one database snapshot.
- Added responsive recovery controls with explicit validation/error states and keyboard focus handling.
- Added nine data regression tests and a browser recovery/output workflow; reran the existing server and UI suites.

## 0.7.1

- Audited existing workflows; no new roadmap features.
- Refined all themes, compacted service cards and result controls, and added visible device review priority.
- Added collapsible assessment setup, mobile revisit behavior, clearer empty-state guidance, focus return, and a skip-to-results link.
- Fixed inspector conflict trapping while retaining drafts, stale search rendering, and latest-scan pagination recovery.
- Fixed JSON export consistency through a single read transaction, explicit selected-scan baseline comparisons, report filter labels, and plain-search metadata noise.
- Fixed identification of fragmented Telnet negotiation bytes.
- Added four automated correctness regressions and a focused browser audit across themes and screen sizes.

## 0.7.0

- Added persistent schedules based on completed scan scopes, with interval editing, pause/resume, run-now, and deletion that preserves history.
- Added a single-scanner scheduler with durable due times, current-scope validation, and no missed-interval replay.
- Added transactional comparison against the last completed repeat or source scan, excluding partial runs.
- Added an inbox for new/missing services, verified protocol changes, and TLS certificate fingerprint changes.
- Added review/reopen, pagination, before/after evidence, source-scan links, and an inbox shortcut.
- Added schedule and inbox records to JSON exports, upgrade migration, and schedule conflict feedback.
- Added scheduler, restart, scope, comparison, review, and desktop/mobile workflow verification.
- Corrected one nested f-string to retain Python 3.10-compatible syntax.

## 0.6.0

- Added structured filters, quoted phrases, AND composition, and excluded terms.
- Added validated search errors, sort controls, and pre-pagination ordering.
- Added server-persisted saved views, revision-safe updates, copies, and deletion.
- Added relative observation ages and exact timestamps in report output.
- Added search help, useful query buttons, and Clear filters.
- Preserved pinned scans outside the recent-history dropdown and added saved views to exports.

## 0.5.0

- Added a device inspector with names, tags, notes, and expected-service flags.
- Added server autosave, revision conflict protection, retained browser drafts, and draft download.
- Added category explanations and practical next steps without changing observed evidence.
- Added focused device/port rescans linked to their source scan and scoped change summaries.
- Added searchable annotations and current device records to exports and reports.
- Migrated existing databases in place without discarding scan history.

## 0.4.0

- Added bounded HTTP/HTTPS root-page metadata and RTSP OPTIONS identification.
- Added TLS version, cipher, certificate fingerprint, and optional certificate fields.
- Added recognizable SSH, VNC, FTP/SMTP, and Telnet greeting detection.
- Added verified-response badges, likely-device labels, and explicit port hints.
- Grouped results by IP with complete matching services per device page.
- Added searchable, persistent protocol evidence and report metadata.
- Preserved expanded details during polling and suppressed contradictory port guesses.
- Added real local HTTP, HTTPS, RTSP, redirect, response-cap, and invalid-TLS fixtures.

## 0.3.0

- Added local interface discovery and a network picker with manual fallback.
- Added a scope preview before starting a scan.
- Added bounded cancellation, durable check outcomes, and interrupted-scan recovery.
- Added coverage warnings for incomplete scans and category ports not included.
- Added result pagination, exact counts, and a dedicated full-result printable report.
- Guarded baseline comparisons against partial or mismatched scan scopes.
- Fixed theme changes dropping interface mode and browser preference recovery errors.
- Corrected port-based service labels to avoid implying verified identification.
- Expanded overview ports to include the focused assessment presets.
- Added regression tests and desktop/mobile screenshots.

## 0.2.0

- Added Easy Mode presets and evidence/confidence findings.

## 0.1.0

- Initial Python/SQLite scanner, browser UI, saved scans, search, baselines, JSON export.
