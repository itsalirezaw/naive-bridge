#!/usr/bin/env bash
# Online bootstrap. For an offline release bundle, use install-local.sh.
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run as root / با کاربر root اجرا کنید.' >&2; exit 1; }
[[ $(uname -s) = Linux && $(uname -m) = x86_64 && -d /run/systemd/system ]] || {
  echo 'NaiveBridge needs Linux x86_64 with systemd.' >&2; exit 1;
}
version="${NAIVE_BRIDGE_VERSION:-v0.1.0}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] || { echo 'Invalid version.' >&2; exit 1; }
if ! command -v curl >/dev/null || ! test -s /etc/ssl/certs/ca-certificates.crt; then
  command -v apt-get >/dev/null || { echo 'Install curl and ca-certificates first.' >&2; exit 1; }
  apt-get update
  apt-get install -y curl ca-certificates
fi
work=$(mktemp -d -t naive-bridge.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
asset=naive-bridge-linux-amd64.tar.gz
base="https://github.com/itsalirezaw/naive-bridge/releases/download/$version"
echo "Downloading NaiveBridge $version / دریافت بستهٔ آماده..."
curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 --max-time 600 "$base/$asset" -o "$work/$asset"
curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 --max-time 60 "$base/SHA256SUMS" -o "$work/SHA256SUMS"
(
  cd -- "$work"
  # Only accept one checksum, for the exact archive about to be installed.
  [[ $(wc -l < SHA256SUMS) = 1 ]]
  LC_ALL=C grep -Eq '^[0-9a-f]{64}  naive-bridge-linux-amd64\.tar\.gz$' SHA256SUMS
  sha256sum --check --strict SHA256SUMS
  tar --no-same-owner -xzf "$asset"
  bash naive-bridge/install-local.sh --no-menu
)
if [[ "${1:-}" != --no-menu ]]; then
  /usr/local/bin/naive-bridge </dev/tty
fi
