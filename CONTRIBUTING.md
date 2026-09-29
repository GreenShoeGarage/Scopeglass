# Contributing to Scopeglass

Scopeglass is a local-first network assessment instrument from Green Shoe Garage, licensed under GNU GPL v3. Keep the runtime dependency-free (Python 3.10+ and a browser), preserve saved data, and make evidence and uncertainty clear.

## Run a development copy

Copy `config.example.json` to `config.json`, review the allowed networks, then run `python3 server.py --config config.json`. The local config and databases are ignored by Git. A release ZIP includes a clean starter config automatically.

Use a temporary database and loopback fixtures for tests. Never scan an unrelated network as part of CI or a pull request. Keep real observations, network details, credentials, private keys, and database backups out of commits and issue attachments.

## Check a change

```sh
python3 -m unittest discover -s tests -v
```

The protocol fixtures require the `openssl` command. Browser suites are development-only dependencies; the application itself makes no npm requests and needs no build step:

```sh
npm install --no-save --package-lock=false playwright@1.62.1
npx playwright install chromium
node tests/browser-smoke.cjs
node tests/browser-audit.cjs
node tests/browser-data.cjs
node tests/browser-access.cjs
```

Use `npx playwright install --with-deps chromium` on a supported Linux CI host that needs browser system libraries. `SCOPEGLASS_BROWSER` can point to an existing Chromium executable. Run suites sequentially; they use local fixture ports 18765–18769 and service ports 2323, 8080, 8443, and 8554. Browser checks rewrite screenshots in `docs/`; review them before committing. Fixture HTTPS certificates are temporary and never enter the release package.

For database/process changes, the separate `test_startup.py` suite exercises real subprocesses, duplicate ownership, crash recovery, startup failure, and graceful Unix shutdown. For packaging and deployments, follow [RELEASE.md](RELEASE.md).

A pull request should explain the problem, resulting behavior, tests actually run, and any data migration or remaining risk. Update the changelog and relevant usage docs. Preserve keyboard focus, mobile layouts, all three themes, draft recovery, and exports when changing the UI. Do not add a cosmetic setting or separate module when an existing control can serve the task.

The GitHub workflow runs Python checks, browser suites, platform ownership checks, and a disposable Docker test before producing a candidate artifact. A workflow file is not evidence that those remote jobs have run; record actual outcomes in the test report.
