# Scopeglass v1.0.0-rc.1 deployment

Use one installation and one server process per database. This candidate enforces ownership with an OS lock beside the database. Leave the `.lock` file in place; the operating system releases ownership after normal exit or a crash. Use local storage, not a network filesystem or a hard-linked database copy. Stop older Scopeglass versions before upgrading: they do not participate in this lock. These examples run the Python server; a static web host cannot run scans or SQLite. The scanner needs ordinary outbound TCP connections, not root or raw-socket capabilities.

## Choose your path

| Use | Start here |
| --- | --- |
| Your own computer | Extract the ZIP; run `python3 server.py --config config.json` |
| Guided setup or a local login | Stop the server; run `python3 server.py --config config.json --setup` |
| Docker on your computer | Follow the Compose steps below |
| A shared server | Enable administrator login, configure an HTTPS origin and private backend, then use the proxy/service examples |

Python 3.10+ is required. The application has no pip dependencies. On Windows use `py` instead of `python3`. The Linux service instructions require systemd and administrative access; they are not executed by the application.

## Guided setup

The terminal wizard offers local access without login, local access with a login, or shared access behind HTTPS. It asks for a port, database, permitted CIDRs, and (when enabled) username/passphrase. It keeps the listener on loopback, saves a copy before replacing an existing configuration, and does not start scans or the server. Review the database path when upgrading; choosing a new file starts an empty installation. Run setup with the server stopped.

```sh
python3 server.py --config config.json --setup
python3 server.py --config config.json --check-config
python3 server.py --config config.json
```

Passphrases require 15–128 characters and are entered through a hidden terminal prompt. There is one administrator account with full access. No default password, public registration, email service, or cloud identity is involved. The web app's **Access & setup** panel shows the active address, database, allowed scope, and runtime.

## Docker Compose

Docker/Compose are optional deployment tools, not application runtime dependencies. The Docker image uses the official Python 3.13 slim image, runs as numeric UID/GID 10001, and writes only to its data volume and temporary directory.

From the extracted `scopeglass` folder:

1. Review `deploy/config.docker.json`, especially the allowed networks.
2. Build the image, then create the account before starting the service:

```sh
docker compose build
docker compose run --rm -it scopeglass python server.py --config /app/config.json --set-password
docker compose up -d
docker compose ps
```

3. Open `http://localhost:8765/` and sign in as `admin`, or the username you supplied with `--username` when setting the password.

The published port is explicitly bound to the host's loopback address. The container listens on `0.0.0.0` internally and requires authentication. For shared access, set `public_origin` to your actual `https://` address, keep the host port private, restart the container, and put the HTTPS proxy in front of it.

`scopeglass-data` retains the database and automatic backups across container replacement and `docker compose down`. **Do not add `--volumes` / `-v` when taking Compose down unless you intend to erase the data volume.** Export JSON or copy a consistent SQLite backup before upgrading. A first-time named volume inherits `/data` ownership from the image; existing volumes or bind mounts must allow UID/GID 10001 to write.

```sh
docker compose logs --tail=100 scopeglass
docker compose restart scopeglass
docker compose run --rm -it scopeglass python server.py --config /app/config.json --set-password
docker compose stop
```

The last command stops scanning; the server handles SIGTERM and stops in-flight work. JSON restore and Fresh Start preserve the administrator account. Password reset revokes all sessions and does not alter assessments.

**Network position:** scanning `127.0.0.1` inside a container checks the container, not the host computer. Network detection may fall back to configured scope because the slim image does not include interface utilities. Enter the actual LAN CIDR manually. Docker bridge routing, host firewalls, and VPN configuration determine which devices are reachable; test a device you control first. This package does not add host networking or privileged access.

## HTTPS reverse proxy

The Python listener does not provide TLS. Set `public_origin` to exactly the browser-facing origin, such as `https://scopeglass.example.com`, and enable `auth.enabled`. No URL subpath is supported. Use a dedicated hostname/root path.

The supplied Caddy example terminates HTTPS and forwards the original Host header. Replace the example hostname in both files. Caddy's certificate issuance needs a valid domain and the network access appropriate to your certificate setup; certificates and DNS are not provisioned by this ZIP. For a private certificate authority, configure that trust on clients explicitly.

Do not publish the Python port directly. A proxy on the same host can reach the loopback listener (or Compose's loopback-published port). If the proxy is on another host, bind a private interface, enable authentication, and restrict backend ingress to the proxy using the host firewall. Forwarded address/protocol headers are deliberately not trusted by Scopeglass; the configured origin determines Secure cookies and allowed Host/Origin values.

With an HTTPS origin, use only that HTTPS URL for the app. Direct browser requests to the backend address are rejected. `/healthz` also accepts the backend's loopback host and returns only readiness/version metadata, for local health checks. The application rejects unauthenticated inventory/API access, cross-origin writes, unrecognized Host values, and stale-session CSRF headers.

## Linux systemd service

Example paths are `/opt/scopeglass` for code, `/etc/scopeglass/config.json` for configuration, and `/var/lib/scopeglass` for data. Adapt them together if needed. Confirm `/usr/bin/python3` is Python 3.10 or newer.

Create a dedicated account if it does not already exist, then install the extracted application and configuration:

```sh
sudo useradd --system --home-dir /var/lib/scopeglass --no-create-home --shell /usr/sbin/nologin scopeglass
sudo install -d -m 0755 /opt/scopeglass
sudo cp -R server.py access.py deployment.py dataops.py monitoring.py protocols.py searching.py static LICENSE /opt/scopeglass/
sudo install -d -m 0750 -o root -g scopeglass /etc/scopeglass
sudo install -m 0640 -o root -g scopeglass deploy/config.service.json /etc/scopeglass/config.json
sudo install -d -m 0700 -o scopeglass -g scopeglass /var/lib/scopeglass
```

Edit `/etc/scopeglass/config.json`: set your HTTPS origin, allowed networks, and database path. For an upgrade, use a consistent copy of the old database and give the service account ownership; preserve the original until verification succeeds. Then:

```sh
sudo -u scopeglass /usr/bin/python3 /opt/scopeglass/server.py --config /etc/scopeglass/config.json --set-password
sudo -u scopeglass /usr/bin/python3 /opt/scopeglass/server.py --config /etc/scopeglass/config.json --check-config
sudo install -m 0644 deploy/scopeglass.service /etc/systemd/system/scopeglass.service
sudo systemctl daemon-reload
sudo systemctl enable --now scopeglass
sudo systemctl status scopeglass
```

Configure the HTTPS proxy and visit the configured URL. The account above cannot edit `/etc/scopeglass/config.json`; configuration changes belong to the host administrator.

```sh
sudo journalctl -u scopeglass --since today
sudo systemctl restart scopeglass
sudo systemctl stop scopeglass
```

The service has a private temporary directory, no extra capabilities, protected system/home paths, and an owned state directory. It needs outbound IPv4 TCP to assessed networks. Update the `WorkingDirectory`, `ExecStart`, and state-directory settings together if relocating the app. Do not run a second interactive server against the service's database.

## Upgrade and rollback

1. Stop the old service and keep a full SQLite backup, its configuration, and the old code ZIP. Preserve any SQLite sidecars together if copying an uncheckpointed database.
2. Extract v1.0.0-rc.1 separately. Retain the existing configuration and absolute database path. A legacy loopback configuration keeps working without login.
3. A non-loopback configuration now requires administrator login. Configure `auth.enabled=true`, an HTTPS `public_origin`, and a private/proxied backend before starting. Create the account with `--set-password`.
4. Run `--check-config`, then start v1.0.0-rc.1. Existing assessment tables are retained; access tables are added when upgrading from before v0.9. Schema version remains 9. A newer, unsupported schema is refused before modification. Previously enabled schedules remain enabled and can run when due.
5. Verify history, an annotation, a saved view, a baseline, and a schedule. Export JSON, reload, and check the visible v1.0.0-rc.1 label.

For rollback, stop Scopeglass and restore the **pre-upgrade database** at a new filename; point the old code/config at that copy. Do not mix one database's `-wal`/`-shm` files with another. Downgrading the migrated database in place is not supported. Reload browser tabs after changing the running version or restored database.

## Access and recovery boundaries

- Sessions last 12 hours, use HttpOnly/SameSite=Strict cookies, and are invalidated by logout, terminal reset, or a password change. HTTPS mode additionally uses Secure `__Host-` cookies. A browser's tabs share its cookie/session.
- Passphrases use salted PBKDF2-HMAC-SHA-256 with 600,000 iterations. Plain passphrases and session bearer tokens are not stored. The database contains password hashes and session-token hashes and must still be protected as sensitive data.
- Writes require the current session's CSRF header and the current dataset epoch. Epoch changes after JSON restore or Fresh Start. Custom API clients must retain the login cookie, take `csrf` from `/api/auth/status`, and use both headers; the ordinary browser manages this automatically.
- Login and password-change attempts share a limit of five per socket peer per minute, plus 30 globally. Behind a local proxy, clients share its peer limit. Limits are process-local and reset on restart; there is no distributed lockout, MFA, SSO, or multi-user authorization in this release.
- JSON exports contain assessment data, not credentials or sessions. JSON restore/Fresh Start leave the login account and active sessions intact. SQLite backups contain the full database, including access tables; protect them accordingly. A SQLite restore can revive sessions/account state from the backup; reset the passphrase to invalidate restored sessions.
- Signing out does not delete inspector drafts or stop schedules. On a shared computer, use Fresh Start only if you intend to clear server data; clear the browser's site storage separately to remove local preferences/drafts without deleting the server's records.
- Scopeglass is intended for personal/small trusted deployments behind a private HTTPS proxy, not direct public exposure of its standard-library development server. Authentication has automated regression coverage, not an independent security audit.

## Verification status and references

See `TEST-REPORT.md` for executed checks and remaining deployment limits. Docker and Caddy binaries were not available in the build workspace, so a container build and real Caddy/systemd deployment are not claimed. The Python backend, HTTPS proxy login flow, config validation, service syntax, process ownership, graceful shutdown, and upgrade fixture are tested separately. See [../RELEASE.md](../RELEASE.md) for the runnable Docker smoke test and remaining stable-release gates.

Primary implementation references: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Docker Compose service settings](https://docs.docker.com/reference/compose-file/services/), [official Python images](https://hub.docker.com/_/python), and [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
