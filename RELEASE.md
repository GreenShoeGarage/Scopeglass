# v1.0 release gates

**Current candidate: v1.0.0-rc.1. Stable v1.0 is pending.** This package is ready for source review and host validation. It has not been published to a repository or deployed to a host by this release process.

## Evidence recorded for this candidate

See [TEST-REPORT.md](TEST-REPORT.md) for executed checks. Keep the following distinction when promoting a release:

| Gate | Candidate status | Required for stable v1.0 |
| --- | --- | --- |
| Python behavior and restart/data recovery | Executed locally; results in test report | Pass on final source |
| Browser workflows, themes, focused accessibility | Executed locally in Chromium | Pass and visually inspect final source |
| Python versions / macOS / Windows ownership | CI jobs supplied; remote jobs not executed here | Record successful CI results or narrow the supported platform statement |
| Docker image / volume / restart | Executable test supplied; Docker unavailable here | Run the test below on a Docker host |
| Real HTTPS proxy and systemd service | Examples and service syntax checked; Node HTTPS fixture passed | Complete the intended-host checks below |
| Real devices / network position | Loopback fixtures only | Verify at least one device you control and record reachability/identification limits |
| Source package | Allowlist, checksums, clean config, integrity checks | Build from the final tested source; attach its hash |

## Docker gate

From a machine with Docker and Compose, in the extracted source folder:

```sh
docker compose config --quiet
docker build -t scopeglass:release-test .
python3 tests/container-smoke.py --image scopeglass:release-test
```

The script creates a randomly named container and volume, a temporary account/configuration, and a loopback-only published port. It checks the actual image's non-root/read-only execution, login, protected inventory, a TCP assessment inside the container, refusal of a second process sharing that volume, persistence across restart, and the Dockerfile health command. It removes only resources it created. It neither reuses nor modifies your installation's data volume. A failure exits nonzero. Image pulls require internet access; runtime assessment stays inside that test container.

Then follow the **actual Compose installation** procedure in [deploy/README.md](deploy/README.md), verify healthy status and login, and confirm that `docker compose down` followed by `up -d` preserves an observation and annotation. Do not use `down -v` on retained data. The isolated test does not establish LAN routing or verify your real Compose setup.

## Intended-host gate

Record the date, OS/Python, Scopeglass version, deployment route, and results in a private validation note. Do not put actual CIDRs, hostnames, reports, or credentials into a public repository.

1. Install using the supplied service/proxy instructions. Confirm the backend is private, the browser-facing origin matches configuration, and `--check-config` reports ready.
2. With your actual hostname in the example, run `caddy validate --config /path/to/Caddyfile --adapter caddyfile` before activating it. Confirm the browser trusts the actual HTTPS certificate, sign-in succeeds, a logged-out inventory request is denied, and the session cookie is Secure/HttpOnly/SameSite=Strict. The local Node test does not establish Caddy or certificate provisioning.
3. For a systemd installation, run `systemd-analyze verify`, start the unit, inspect status/logs, and restart it. Confirm the dedicated user can write its database/backups and can reach a device you control.
4. Run an Easy assessment against that device, inspect evidence, rename it, add a note, mark an expected service, and save a view. Reload and restart the service; verify all saved state. Check the mobile workflow and keyboard focus on the browser(s) you intend to support.
5. Export JSON. In a separate disposable installation, preview/restore it, verify history/annotations/views, and confirm restored schedules are paused. Keep the original installation and backup untouched.
6. In that disposable installation, start a sufficiently long loopback assessment, stop the service, and restart. Confirm saved checks and a cancelled/interrupted status. Kill/restart recovery is separately covered by the subprocess test suite.
7. Verify upgrade from your previous version and rollback to a pre-upgrade SQLite backup at a new filename. Reset the passphrase before serving a restored SQLite backup. Confirm enabled schedules will run only on your intended network.

## Build the source package

```sh
python3 scripts/release.py
```

This writes `dist/SCOPEGLASS-v1.0.0-rc.1.zip` and its `.sha256` file. The ZIP contains a `scopeglass/` folder and a `SHA256SUMS` manifest. It includes a clean `config.json` derived from `config.example.json`; it never copies your local `config.json`, databases, backups, private keys, caches, or dependencies. File order, metadata, and timestamps are normalized so identical source inputs produce identical ZIP bytes. Screenshots are inputs, so regenerating them changes the package hash.

Extract to an empty directory, verify the manifest (`sha256sum -c SHA256SUMS` on Linux), then run config check, tests, and a loopback assessment from the extracted package. Preserve the exact ZIP/hash alongside the test evidence.

## GitHub handoff and stable promotion

The repository root is the **contents** of `scopeglass/`, including `.github/`. Create/push a repository only when the owner chooses a destination. Review the initial file list with `git status`; local configuration and data are ignored. Enable private vulnerability reporting if supported by that repository. The supplied Actions workflow has read-only repository permissions and creates downloadable CI artifacts; it does not publish a release, push changes, or deploy a server.

After all required gates pass, update the version in `server.py`, `static/index.html`, `compose.yaml`, README, and release documents. Add the stable version to JSON restore's explicit supported-version check without removing support for this candidate's exports. Keep SQLite schema version 9 unless the database structure actually changes. Run checks again, update the test report/changelog, build from the tested source, and mark the GitHub release appropriately (this candidate is a prerelease). Do not label the candidate stable merely because a package was generated.
