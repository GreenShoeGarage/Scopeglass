# Scopeglass v0.7.1 — existing-product audit

The existing assessment workflow is usable and passed the checks below after correction. This release improves v0.7 rather than adding the next roadmap milestone. It does not establish that the app is free of all defects or ready for an unauthenticated public deployment.

## Findings and corrections

| Finding | Why it mattered | Correction |
| --- | --- | --- |
| Inspector Close/Escape waited for a successful save | A revision conflict or disconnected server could trap the user in the dialog | Preserve the draft, explain its recovery boundary, close the inspector, and return keyboard focus |
| Export used separate database reads | A running scan could commit between records, making counts and observations disagree | Read all export tables within one SQLite snapshot; tested with a real concurrent writer |
| Latest-scan pagination retained its previous offset | A new small scan could appear empty when the earlier scan had multiple pages | Reset the page when the scan changes or the page falls outside the result count |
| A delayed query could render under newer text | Debounced input could temporarily label old results with a new query | Invalidate outstanding requests on input and check the captured query before rendering |
| Baseline comparison always used the latest scan | Reviewing a historical scan could lead to comparison against a different assessment | Compare the selected scan and identify both scan numbers in the result |
| Fragmented Telnet negotiation stopped after its first byte | A valid protocol could be left unidentified depending on TCP packet timing | Wait for a complete bounded negotiation command; tested with separated byte writes |
| Plain search included annotation bookkeeping | Revision numbers and unrelated expected-port lists could create puzzling matches | Limit annotation text to names, tags, and notes |
| Report labels were read again after data loading | Changing filters while a report loaded could mislabel the report | Capture filter labels at the request’s start |
| Repetitive controls and explanatory blocks displaced evidence | Desktop and mobile screens required avoidable scrolling | Combine recurring controls; put routine scope detail behind a disclosure; keep incomplete-coverage warnings visible |
| Save state and first-use guidance were ambiguous | “Saved” could imply every kind of data, while empty results offered little direction | Label browser settings explicitly and offer a direct route to the network controls |

## Interface refinements

The visual system retains Green Shoe Garage’s dark instrument character and lime accent. It now uses clearer heading sizes, quieter secondary text, more consistent spacing and borders, aligned service rows, simple device symbols, and visible textual review priorities. Expected services retain their original severity and evidence.

All existing features remain reachable: Easy/Advanced scanning, network selection, cancellation, history, structured search, saved views, annotations, expected services, focused rescans, baselines, scheduling, change review, JSON export, and printable reports. On mobile, returning users can review results with setup collapsed. Setup remains available, and scan progress and cancellation remain outside the disclosure.

The review did not add decorative charts, new navigation screens, external fonts, telemetry, a build system, or a runtime dependency.

## Verification

- **30 Python tests passed**, covering scanner behavior, persistence, migration, cancellation, protocols, search, schedules, change review, and the audit regressions.
- **Complete browser workflow passed** using a real Python service and controlled loopback HTTP/HTTPS/RTSP/Telnet fixtures. This includes report/PDF generation, save conflicts, restart recovery, schedule runs, and review-state persistence.
- **Focused browser audit passed** for empty-state guidance, live pagination, delayed search responses, mobile revisit behavior, and inspector Escape/focus return.
- **Responsive checks passed** at 320, 390, 768, and 1280 pixels; the main workflow also ran at desktop 1440 and mobile 390 pixels.
- **Measured core text contrast passed** at 4.5:1 or above in dark, light, and high-contrast themes. This covered body, field, active-mode, and note text against their rendered solid backgrounds.
- No uncaught JavaScript errors were observed. The full workflow made no external browser asset requests.

Screenshots and reproducible tests are included. `TEST-REPORT.md` describes the fixtures and precise limits.

## Remaining boundaries

Device labels remain inferences from public protocol evidence; a camera label is not proof of physical identity, and an observed service is not proof of internet exposure. Missing responses can be temporary or filtered. Certificate trust is not evaluated.

This audit used Chromium and controlled services. It does not substitute for Safari/Firefox testing, a complete screen-reader audit, real-device identification validation, or a days-long scheduling/load test. Platform interface detection on Windows/macOS remains fixture-tested.

Authentication/deployment hardening and validated import/restore remain roadmap work. JSON exports are still archival; restore uses a SQLite backup. None of those deferred capabilities are claimed complete by this maintenance release.


## v0.8 follow-up

This file records the v0.7.1 audit. v0.8 subsequently delivers validated JSON restore, CSV, report refinements, manual cleanup, and Fresh Start. The archival-only statement above describes v0.7.1; it no longer describes the current release. See `README.md` for recovery procedures and `TEST-REPORT.md` for current verification. Authentication and guided deployment remain future work.


## v0.9 follow-up

Administrator authentication and guided deployment files are now included, with local access preserved. `TEST-REPORT.md` documents 51 Python regressions, the HTTPS browser workflow, and the deployment execution limits. The earlier roadmap statements in this historical audit describe the versions reviewed at the time. Live Docker/Caddy/systemd deployment verification and the final v1.0 release review remain.


## v1.0.0-rc.1 release review

The final local review found that startup recovery could modify a live database before a second listener failed to bind. The candidate adds process ownership before recovery, reserves the port before migration, and waits for active work to save before releasing ownership during graceful shutdown. Unsupported future schemas now fail before modifications. Six subprocess tests cover these boundaries, including forced termination and restart.

The README now leads with the user's tasks rather than a long sequence of release feature lists. UI visual/keyboard/contrast checks and browser workflows are repeated for the candidate. Packaging and deployment gates are reproducible through the supplied scripts and GitHub workflow; availability of a workflow is not proof of a successful remote run. See RELEASE.md and TEST-REPORT.md for remaining host/platform gates.
