# Scopeglass v1.0.0-rc.1 verification

Executed locally on 2026-09-27. Runtime: Python 3.12.14, Node 24.19.0, Playwright 1.62.1 with Chromium 134. All network assessments used loopback fixtures. **This is a release candidate; remote CI and actual Docker/Caddy/systemd installation have not run here.**

## Candidate startup/shutdown gates: 6 passed

These tests launch real Python subprocesses with temporary SQLite files:

- A second server on a different port cannot claim the same database or mark its running scan interrupted.
- An occupied listener port leaves an older database byte-for-byte unchanged and releases its ownership lock.
- Forced process termination releases the OS lock without removing the sidecar; a new process recovers interrupted state and preserves observations.
- A database marked with a future schema version is rejected unchanged by startup, config checking, and terminal password reset.
- Guided setup refuses a live database without replacing its configuration or writing a backup.
- SIGTERM waits for an active scan to save matching check counts and cancelled state, then releases ownership.

The macOS/Windows ownership CI jobs are provided but not executed here. The Windows job intentionally skips the Unix SIGTERM case; Windows forced termination uses restart recovery. Older Scopeglass releases do not participate in the new lock and must be stopped before upgrading.

## Candidate source and UI review

- All four browser suites passed against the candidate. Fresh screenshots were generated; mobile results, desktop light theme, mobile login, and the account/setup panel were visually inspected. The longer candidate version fits the reviewed layouts.
- Main JavaScript passed `node --check`; all Python sources parse under Python 3.10 syntax. HTML IDs are unique and relative Markdown links resolve.
- Four shipped configurations pass the validator. Compose and GitHub workflow YAML parse and their declared jobs/dependencies/loopback binding were checked structurally. This does not substitute for executing those jobs.
- `systemd-analyze verify deploy/scopeglass.service` passed with no diagnostics.
- Runtime code changes were reviewed against v0.9.0. Schema remains 9; restore accepts candidate exports and previous v0.3–v0.9 archives.

## Extracted source package: passed

- ZIP integrity and every manifest checksum were checked; no databases, bytecode, lock files, private keys, or live configuration were packaged.
- The included starter config matches `config.example.json`. `--check-config` from a clean extraction reports ready without creating data.
- Rebuilding from the extracted source produced byte-for-byte identical ZIP content.
- The extracted application started, completed a real loopback TCP assessment, exported its observation, and exited cleanly on SIGTERM.
- These checks do not establish Docker execution or actual host deployment. The source includes a runnable container check and explicit remaining gates in RELEASE.md.

## Server and protocol regression tests: 57 passed

Run `python3 -m unittest discover -s tests -v`.

- Scope enforcement, duplicate target handling, oversized/IPv6 rejection, and preset preview without starting a scan.
- Real loopback TCP connection observation and durable check outcome, export, and baseline creation.
- Cancellation stops new work, completes at most the bounded in-flight set, persists partial results, and refuses a partial baseline.
- Restart recovery retains saved counts and marks unfinished scans interrupted; v0.2 schema migration preserves existing rows.
- Linux, macOS, and Windows interface-output parsers with representative fixtures, including larger-network /24 suggestions.
- Category filtering before pagination, exact result counts, and refusal of different-scope baseline comparisons.
- Invalid API input and conservative camera classification.

Additional v0.4 protocol tests use real local HTTP, HTTPS, and RTSP servers:

- HTTP titles, chunked response bodies, bounded response reads, and advertised metadata.
- Redirects recorded without following their destination.
- RTSP 401 response identified from an OPTIONS request, without sending credentials.
- Self-signed HTTPS: title, TLS version, fingerprint, subject, and explicit unevaluated trust.
- Protocol evidence overrides contradictory port hints; plain login text stays unverified while Telnet IAC negotiation is recognized.
- Failed TLS identification preserves the successful TCP connection observation.
- Device pagination keeps all matching services for a host on the same page (targeted server test rerun after extending this assertion).

The TLS tests use the local `openssl` command to generate an ephemeral fixture certificate. There is no certificate-generation or OpenSSL command dependency in the application itself.

Additional v0.5 server tests verify annotation persistence, optimistic revision conflicts, expected-service flags without severity changes, annotation search and export, invalid port rejection, focused rescan lineage and missing-service results, retained source observations, and current scope enforcement on rescans.

Additional v0.6 tests cover combined filters, quoted phrases, excluded tags, range and age boundaries, invalid input, verified protocol versus service hint semantics, numeric IP/port ordering, and saved-view create/update/conflict/delete/export/persistence. 

Additional v0.7 tests cover schedule creation and edit validation, stale-revision conflicts, pause/resume/delete, persistence, due-time claims, scanner contention, no catch-up replay, interrupted-run recovery, allowlist revalidation and automatic pause, partial-run comparison protection, protocol/certificate/missing/new change evidence, deduplication, review/reopen, 30-entry inbox pagination, and export. The complete 26-test suite passed after the scheduling and migration changes. Schedule timing tests advance the reference clock; probe outcomes are controlled fixtures.

Additional v0.7.1 tests verify that a writer can commit during export without producing mixed scan/check/observation data; that a selected historical scan is used for comparison; that fragmented Telnet IAC bytes still identify the protocol; and that plain search ignores internal annotation revisions and expected-port lists. The v0.7.1 30-test suite passed before the current additions. Python source also parses with Python 3.10 syntax rules; runtime checks used the workspace Python runtime.

## v0.8 recovery and output regressions: 9 passed

- Complete JSON round trip across all eight data tables, retained review state, paused schedules, and no automatic scan launch.
- Pre-change SQLite backup integrity, original schedule state and dataset identity, and closed backup connections with no lingering sidecars.
- Rejection of invalid versions/schema, coverage, duplicate observations, missing references, wrong-scope evidence, invalid metadata/timestamps, cyclic or forward lineage, malformed annotations, and oversized archives; no data changes or backup creation on failed validation.
- Exact confirmation phrases, action/archive binding, expired tokens, and invalidation after another data change.
- Simulated backup disk failure and insertion failure leave the live database and identity unchanged through transaction rollback.
- Fresh Start clears all eight tables, retains configuration/backups, and old client writes fail even after IDs are restored.
- Cleanup removes only eligible scans and their observations/checks; annotations, baselines, pinned views, schedules, changes, the latest scan, and lineage remain valid.
- A legacy-shaped v0.3 archive restores partial scans as interrupted; restoring historical addresses does not bypass the current allowlist for future scans. Active scans block maintenance.
- Reports include all 128 services beyond ordinary pagination, respect a 106-service filter, and retain one consistent read snapshot during a concurrent commit.

The full 39-test suite passed; targeted recovery tests were rerun after the backup connection and reference-validation fixes. Failure tests inject exceptions; they do not simulate actual disk exhaustion or hardware power loss.

## v0.9 access and deployment regressions: 12 passed

- Every inventory and write route rejects unauthenticated access in login mode; the app shell, auth status, and minimal health endpoint remain public.
- Login issues HttpOnly/SameSite=Strict cookies, stores password/session hashes, and requires CSRF on authenticated writes. Logout revokes the cookie/session.
- Incorrect username/password responses are generic; the sixth attempt within the peer window is throttled with Retry-After, then becomes eligible after the test clock advances.
- Passphrase changes reject incorrect/short inputs, revoke other sessions, and retain a newly issued current session. Expiry and a 20-session storage bound are enforced.
- Unrecognized hosts, cross-origin writes, mismatched schemes, null Origin, and cross-site fetch metadata are rejected. Forwarded headers do not change authorization. HTTPS origins issue Secure `__Host-` cookies.
- JSON restore/Fresh Start preserve the account and sessions, while JSON export omits access tables and secrets.
- Legacy local access remains functional without authentication; invalid/non-loopback anonymous settings, unknown authentication settings, invalid ports, non-HTTPS shared origins, credential-bearing URLs, URL paths, and IPv6 scan scope are rejected.
- Password salts differ, hashes verify correctly, terminal reset revokes sessions, and invalid passphrase inputs fail.
- Guided authenticated setup creates a config/account; a read-only config/account readiness check does not migrate the database. Cancelling an overwrite preserves the config.
- Startup with authentication enabled but no account fails before listening, scheduling, or migrating assessment tables.
- `tests/fixtures/v0.8.sql` was generated using the shipped v0.8.0 server and synthetic loopback records across all eight assessment tables. Two consecutive upgrades preserve every record, add access tables, keep the account empty until configured, and produce a valid current JSON archive.

The full 57-test candidate suite passed on Python 3.12.14 (47.142 seconds). Source syntax also passed Python 3.10 parsing; this is not a claim of executing all supported Python versions.

## Browser workflow: passed

Chromium 134 via Playwright, desktop 1440 × 1100 and mobile 390 × 844. Real Python server and local TCP fixtures on ports 2323, 8080, 8443 (HTTPS), and 8554; a dynamically assigned slow fixture tests cancellation/recovery. Network-picker metadata is a deterministic test fixture. No third-party network scans.

Verified:

- Network picker populates the scope and updates the preview.
- Easy preset scanning, Telnet category results, and unscanned-category coverage warnings.
- Advanced custom scan and Stop scan, with partial observations retained.
- Actual server process kill/restart during a scan; interrupted state and saved progress survive.
- Form preferences and theme survive reload; Easy/Advanced mode and all themes respond.
- Category and text filtering, baseline creation/comparison, JSON download.
- Dedicated printable report opens and successfully generates a PDF.
- No horizontal page overflow at mobile width; the wide data table has its own horizontal scrolling area.
- Keyboard Tab/Enter operates the mode switch; desktop and mobile screenshots visually inspected.
- Device view groups all four observed fixture services under one IP, shows likely-device confidence and verified Telnet/HTTP/HTTPS/RTSP response badges.
- Certificate subject/trust details render correctly, metadata is searchable, and expanded details remain open across polling.
- Inspector editing, autosave, expected flags, names/tags/notes surviving reload, and safe literal rendering of HTML-like notes.
- Concurrent modification from another API client produces a visible conflict; draft download and confirmed reload preserve user control of edits.
- A real fixture service is stopped, and a focused rescan records it as no longer observed while preserving the original four-service scan.
- Device rescan checks the original 25-port scope for one host and produces a scoped comparison.
- Annotated reports include current device names, notes, and expected-service status; the mobile inspector fits the viewport and closes through Escape.
- Structured search, explicit invalid-query feedback, sort selection, expected/verified combinations, and age filtering.
- Saved views survive reload, restore a pinned scan and sort/filter settings, update, and delete without creating a scan. Relative observation labels render.
- Schedule creation uses the full source scope without starting an immediate scan; pause, interval/name edits, resume, reload, and concurrent-edit recovery.
- A real server scheduler thread launches an overdue assessment after the test database due timestamp is moved into the past. It records the stopped loopback Telnet service as no longer observed, with its refused-connection evidence.
- Inbox review, reopen, persistence after reload, evidence expansion across polling, and source-scan navigation.
- Run-now while paused compares against the previous completed repeat and reports zero further changes; deleting the schedule preserves inbox history.
- Desktop and mobile schedule/inbox layouts and horizontal overflow.
- Closing the inspector after a revision conflict preserves the draft; reopening restores it and allows explicit recovery.
- No uncaught JavaScript errors or external browser requests during the workflow.

Optional reproduction (Node 18+, the `openssl` command, and test-only Playwright installation required):

```
npm install --no-save playwright
npx playwright install chromium
node tests/browser-smoke.cjs
```

The browser test uses Chromium dialog controls for conflict recovery and needs free local ports 18765, 2323, 8080, 8443, and 8554, creates a temporary database, and regenerates the screenshots in `docs/`. Set `SCOPEGLASS_BROWSER` to use an existing Chromium executable. These are development dependencies; the application itself needs only Python.

## Focused UI audit: passed

Run `node tests/browser-audit.cjs` with the same Playwright/Chromium setup. This uses a separate temporary database and port 18766, seeded with clearly synthetic loopback evidence; it does not scan a network.

- Empty-state guidance focuses the network input and keeps scanning disabled until the scope is valid.
- A live switch from a 26-host scan’s second page to a one-host latest scan resets pagination correctly.
- A delayed old search response cannot overwrite results for the newer query.
- Dark, light, and high-contrast body text, input text, active-mode text, and note text each meet 4.5:1 against their rendered solid background in the measured theme pairs. This is a focused contrast check, not an exhaustive accessibility certification.
- Mobile revisit collapses setup after existing observations load; setup remains operable.
- No page overflow at 320, 390, 768, or 1280 pixels. Inspector fits each tested viewport, Escape closes it, and keyboard focus returns to the originating button or results heading.
- Screenshots visually reviewed: desktop, mobile, empty state, populated light theme, and the existing inspector/schedule surfaces. All three theme screenshots are included.

## v0.8 browser recovery/output workflow: passed

Run `node tests/browser-data.cjs` with the same Playwright setup. It uses port 18767 and a temporary database containing synthetic loopback history, with no network scan.

- Downloads and restores a JSON archive through the visible controls; invalid JSON produces actionable feedback without mutation.
- CSV exports the filtered rows, preserves commas/quotes/newlines, includes a UTF-8 BOM, and neutralizes leading formula-like annotation text with an apostrophe.
- Printable report includes a review summary, readable protocol evidence, next steps, all rows, and literal escaped HTML-like titles; PDF creation succeeds.
- Recovery preview shows counts and paused-schedule warnings; actions stay disabled until the exact phrase is entered.
- Cleanup preserves a baseline/schedule source while removing the unreferenced older scan.
- Fresh Start clears server data and current-browser settings/drafts; JSON restore returns the data with schedules paused.
- The completion notice exposes the server backup path, three maintenance operations create three standalone SQLite backup files, and a stale second tab cannot write into replaced data.
- Recovery dialog fits 320/390/768/1280px widths, scrolls on narrow screens, focuses confirmation after preview, and returns focus after Escape. Desktop/mobile screenshots were visually reviewed.
- Zero uncaught JavaScript errors in this workflow.

## v0.9 HTTPS browser workflow: passed

Run `node tests/browser-access.cjs` with Playwright, Chromium, and OpenSSL available. It uses a real Python server on loopback port 18768, a Node HTTPS reverse-proxy fixture on 18769, and a temporary self-signed localhost certificate. Browser certificate errors are ignored only for this controlled fixture. This verifies the proxy transport flow, not public certificate provisioning or Caddy itself.

- Unauthorized inventory is rejected and the workspace remains hidden until sign-in. Incorrect passphrase feedback retains the username, clears the passphrase, and permits recovery.
- Password visibility toggles, Secure/HttpOnly/SameSite cookie properties, and the cookie's absence from JavaScript are checked.
- Expiring the real database session during an inspector edit hides the workspace and preserves the draft; signing in recovers/saves it.
- An authenticated Advanced scan connects to a real loopback SSH-greeting fixture and persists its observation.
- Restart preserves unexpired sessions and assessments. Passphrase change revokes another browser context, while the current context remains signed in.
- A cross-origin write is rejected through the real HTTPS proxy. Authenticated Fresh Start/JSON restore retain login, data returns correctly, and credentials remain outside JSON export.
- Sign-out hides the workspace; the new passphrase signs in and survives reload. Theme preferences persist.
- Login and account panels fit 320/390/768/1280px widths; desktop/mobile/light screenshots were visually reviewed; Escape returns account-panel focus.
- No uncaught JavaScript errors or external browser asset requests. All four browser suites also passed on v1.0.0-rc.1.

## Deployment-file verification

- All four provided JSON configurations passed the application validator.
- Compose YAML parsed and its loopback port binding, named data volume, read-only filesystem, dropped capabilities, and no-new-privileges setting were checked.
- `systemd-analyze verify deploy/scopeglass.service` passed with no diagnostics.
- Docker image contents explicitly exclude databases, local configuration, tests, and development files. CLI setup/account-check paths and the backend health endpoint were executed outside Docker.
- Docker/Compose and Caddy binaries were unavailable. No image build, container run, public HTTPS/certificate provisioning, or live systemd installation is claimed. Those are v1.0 deployment gates, along with testing on the intended host/network.

## Limits of verification

- macOS and Windows detection were checked with command-output fixtures, not on physical machines running those operating systems.
- Tested network services are controlled fixtures. Device identification accuracy across real camera brands is not established. TLS trust, hostname matching, and certificate-expiration findings are not implemented; validity dates are shown as metadata only.
- Keyboard and contrast coverage are focused checks, not a full accessibility audit or screen-reader certification. Safari and Firefox were not exercised.
- No days-long wall-clock schedule soak test, system-clock jump test, or load test of long-running production inventories, public deployment, database disk exhaustion, or hardware power loss.
- Authentication has automated functional/boundary coverage, not an independent security audit. MFA, SSO, multi-user roles, distributed login throttling, and direct public-server hardening are outside this release.
- The application requires its local server even when the internet is unavailable. Browser tests confirm no external asset requests, not a standalone offline browser mode.
