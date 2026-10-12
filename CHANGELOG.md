# Changelog

## 0.1.3

- Automatically obtain certificates through the official Certbot Nginx authenticator when host Nginx is active, without stopping it or installing TLS into its websites.
- Back up and validate Nginx configuration; use standalone issuance when Nginx is inactive and TCP 80 is free.
- Preserve Certbot's renewal method and reuse an active Certbot timer, or create a certificate-specific renewal timer if none is active.
- Migrate existing standalone renewals to Nginx with a validated Certbot reconfiguration; preserve existing webroot/DNS methods and reject unsafe custom-hook migrations.
- Reload renewed certificates in the bundled Caddy via SIGUSR1 instead of restarting the tunnel. Ignore unrelated certificates and stopped nodes.
- Refresh renewal hooks for existing nodes during installation and with `naive-bridge refresh-certificates`.

## 0.1.2

- Suggest the outside public IP; Enter accepts it and manual override remains available.
- Prefer free HTTPS ports starting with 443; select a free internal backend automatically, including for CLI setup.
- Detect matching existing certificates and suggest fullchain/key paths; retain certbot auto issuance when needed.
- Validate each setup answer immediately and retry only the invalid field, with clear English errors for port numbers or directories entered as certificate files.
- Check IPv4 and IPv6 listeners when selecting free ports.
- Add the author's GitHub and YouTube links to the English menu footer.

## 0.1.1

- Use English throughout the CLI: menus, prompts, installer messages and errors.
- Keep the Persian installation and panel guides, updated to match the English menu.
- Publish a refreshed offline bundle and point the online installer to v0.1.1.

## 0.1.0

- Initial public NaiveBridge release based on the tested Web Bridge prototype.
- NaiveProxy HTTPS transport, with Xray XHTTP TCP fallback and UDP support.
- Persian setup menu; one-command and offline installation.
- Local SOCKS integration with Iran panels and multiple outside nodes.
- Start, stop, restart, diagnostics and pairing-code management.
- Persian installation, 3x-ui/PasarGuard and operations documentation.
- Allowlisted release packaging and SHA256 verification.

Experimental release: no claim of undetectability, no automatic CDN mode, no ARM64 bundle, and no seamless migration of established connections.
