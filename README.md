# NaiveBridge

**[راهنمای کامل فارسی نصب و اتصال به پنل ایران](README.fa.md)** · [Panel guide / راهنمای پنل](docs/panels.fa.md)

[![Tests](https://github.com/itsalirezaw/naive-bridge/actions/workflows/test.yml/badge.svg)](https://github.com/itsalirezaw/naive-bridge/actions/workflows/test.yml)
[![MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Server-to-server tunneling powered by **NaiveProxy and Chromium's network stack**. Keep users, subscriptions and accounting on your Iran panel; outside servers provide Internet egress.

- Primary TCP transport: NaiveProxy over HTTPS / HTTP/2 with certificate verification.
- TCP fallback and UDP: VLESS/XHTTP over TLS, using Xray.
- Multiple outside nodes, local SOCKS outbounds and automatic failover for new connections.
- English setup menu with suggested public IP, free ports and existing certificate paths; Persian documentation and an offline release bundle.

**Experimental v0.1.4.** This packages existing transport engines; it does not introduce a new protocol or guarantee resistance to traffic identification or blocking. [Test scope and limitations](docs/testing.fa.md) · [Upstream projects](THIRD-PARTY.md).

## Install

Run as root on **Outside first, then Iran**. Requires Linux x86_64, systemd and Python 3.10+. Ubuntu 22.04/26.04 were used for the prototype's live transport tests. The installer installs missing Debian/Ubuntu runtime packages. ARM64 is not supported in this release.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/naive-bridge/main/install.sh)
```

If curl is missing: `apt-get update && apt-get install -y curl ca-certificates`.

1. Point a DNS-only hostname to Outside. Allow the selected HTTPS port and public TCP 80 for automatic certificates. Active host Nginx handles validation through its official Certbot plugin with graceful reloads; otherwise TCP 80 must be free for standalone issuance.
2. On Outside, choose **1**. Enter a node ID and hostname; verify and accept the suggested public IP, free HTTPS port and matching certificate paths with Enter, or override them. The internal port is selected automatically. If no matching certificate exists, Enter selects automatic issuance. Copy the secret `NB1.` pairing code.
3. On Iran, choose **2** and paste the complete code, then press Enter. Input is visible and the accepted node/destination are shown. Free local ports are selected and saved automatically; existing nodes keep their ports. Repeat for additional nodes with distinct IDs.
4. Run `naive-bridge doctor`, then `naive-bridge panel`. Add the generated SOCKS outbounds to the Iran panel and route a test inbound to `naive-bridge-auto`.

The panel configuration is manual: the installer does not change its users, database or routing. No panel is needed on Outside. [Persian 3x-ui / PasarGuard guide](docs/panels.fa.md).

Each successful node setup displays a prominent completion message and the next step, and waits for Enter before returning to the menu. Outside pairing codes appear between BEGIN/END labels: copy only the complete `NB1.` line. Menu option **7** shows the code again. Keep the visible code out of recordings.

Iran's local panel/API/transport ports are independent of Outside's public HTTPS port. Occupied defaults are skipped during initial setup; fallback ports are selected from 20400-29999 and stored in `/etc/naive-bridge/iran.json`. Use the actual ports from option **4**, not a guessed `20080`. No Iran SOCKS/API port needs to be opened publicly. Outside firewall reachability must still be checked from Iran.

Certificate issuance and renewal do not stop host Nginx. Its configuration is validated and backed up before Certbot runs. Renewal uses an existing Certbot timer or a generated certificate-specific timer; the tunnel loads renewed certificates without restart. Nginx in Docker or a custom non-systemd Nginx installation is not automatically managed. [Certificate operation details](docs/operations.fa.md#گواهی).

GitHub unavailable on Iran? Copy the archive and `SHA256SUMS` from [Releases](https://github.com/itsalirezaw/naive-bridge/releases) to both hosts and follow the [offline instructions](README.fa.md#نصب-آفلاین).

## Manage

```bash
naive-bridge            # English menu
naive-bridge status
naive-bridge doctor    # run on Iran; real TCP and UDP checks
naive-bridge panel
naive-bridge restart
naive-bridge stop
naive-bridge start
```

SOCKS/API listen only on loopback. No host default route or firewall rules are changed. If every configured route fails, selected tunnel traffic is blocked; it does not fall back to direct Iran egress. Existing connections cannot migrate between nodes. Adding/removing a node restarts the local router.

Use a free HTTPS port on Outside, or configure an existing TCP/SNI proxy as described in [operations](docs/operations.fa.md). Ordinary Cloudflare orange-cloud proxying is **not supported** by this release. NaiveProxy and XHTTP both dial Outside directly.

## Build and license

On Linux x86_64 with Python 3.10+, run `bash build-bundle.sh`. Pinned upstream downloads are verified; Caddy is built with the Naive forwardproxy plugin. Output: `dist/naive-bridge-linux-amd64.tar.gz` and `dist/SHA256SUMS`.

NaiveBridge code: [MIT](LICENSE). Bundled engines retain their respective licenses; see [THIRD-PARTY.md](THIRD-PARTY.md) and `licenses/`.
