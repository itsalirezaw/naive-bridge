#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ $(id -u) = 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $(uname -s) = Linux && $(uname -m) = x86_64 && -d /run/systemd/system ]] || { echo 'NaiveBridge requires Linux x86_64 with systemd.' >&2; exit 1; }
missing=()
for package in python3 openssl ca-certificates libnss3; do
 if command -v dpkg-query >/dev/null && ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q '^install ok installed$'; then
  missing+=("$package")
 fi
done
if (( ${#missing[@]} )); then
 command -v apt-get >/dev/null || { echo 'Install python3, openssl, ca-certificates and libnss3.' >&2; exit 1; }
 apt-get update
 apt-get install -y "${missing[@]}"
fi
command -v python3 >/dev/null
command -v openssl >/dev/null
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ is required"'
bin_dir="${NAIVE_BRIDGE_BIN_DIR:-$PWD/bin}"
[[ -f "$bin_dir/SHA256SUMS" ]] || { echo 'Missing verified binaries. Run build-bundle.sh on the outside server first, or use a prepared bundle.' >&2; exit 1; }
( cd -- "$bin_dir"; sha256sum -c SHA256SUMS )
for engine in naive xray caddy; do
 [[ -f "$bin_dir/$engine" && ! -L "$bin_dir/$engine" ]] || exit 1
done
install -d -m 755 /opt/naive-bridge /opt/naive-bridge/bin
install -d -m 700 /etc/naive-bridge /var/lib/naive-bridge
# Do not rewrite active engine files. A version-changing upgrade needs a maintenance window.
for engine in naive xray caddy; do
 if [[ -e "/opt/naive-bridge/bin/$engine" ]]; then
  cmp -s "$bin_dir/$engine" "/opt/naive-bridge/bin/$engine" || { echo 'Installed engine differs. This prototype does not upgrade engine binaries automatically; use the current bundle.' >&2; exit 1; }
 fi
done
for engine in naive xray caddy; do
 if [[ ! -e "/opt/naive-bridge/bin/$engine" ]]; then
  install -m 755 "$bin_dir/$engine" "/opt/naive-bridge/bin/$engine"
 fi
done
cp -a naivebridge /opt/naive-bridge/
install -m 644 VERSION LICENSE THIRD-PARTY.md /opt/naive-bridge/
cp -a licenses /opt/naive-bridge/
cat > /usr/local/bin/naive-bridge <<'EOF'
#!/bin/sh
export PYTHONPATH=/opt/naive-bridge
export PYTHONUTF8=1
exec /usr/bin/python3 -m naivebridge.manager "$@"
EOF
chmod 755 /usr/local/bin/naive-bridge
echo 'Installed. Use: naive-bridge'
if [[ "${1:-}" != --no-menu ]]; then exec /usr/local/bin/naive-bridge; fi
