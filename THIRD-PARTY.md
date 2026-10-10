# Upstream engines

NaiveBridge is an orchestration prototype; cryptographic transports are upstream projects.

- NaiveProxy v154.0.8037.49-4: https://github.com/klzgrad/naiveproxy/tree/v154.0.8037.49-4 — Chromium/BSD licenses and third-party notices.
- Xray-core v26.9.30: https://github.com/XTLS/Xray-core/tree/v26.9.30 — MPL-2.0.
- Caddy v2.11.7: https://github.com/caddyserver/caddy/tree/v2.11.7 — Apache-2.0.
- Naive forwardproxy commit c096d6a00cb28e019cc1995b04bdc6a9311d8024: https://github.com/klzgrad/forwardproxy/tree/c096d6a00cb28e019cc1995b04bdc6a9311d8024 — Apache-2.0.
- xcaddy v0.4.7 and Go 1.27.2 are build tools. Go modules are verified by the Go checksum database during the build.

Published archive checksums are pinned in tools/build.py. A prepared bundle includes a per-binary SHA256SUMS file. Source and corresponding upstream licenses remain available at the versioned links above. Keep upstream license/notice files with redistributed engine binaries.
