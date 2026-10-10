#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ $(uname -s) = Linux && $(uname -m) = x86_64 ]] || { echo 'Linux x86_64 required.'; exit 1; }
command -v python3 >/dev/null
python3 tools/build.py
echo 'Offline-ready bundle created: dist/naive-bridge-linux-amd64.tar.gz'
