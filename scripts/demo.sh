#!/usr/bin/env sh
# Cursiv Robotics: one-command demo (Linux/macOS). See scripts/demo.ps1 for Windows.
set -e
cd "$(dirname "$0")/.."
python3 -c "import cryptography" 2>/dev/null || python3 -m pip install --user cryptography
cargo build --release
exec python3 python/cursiv_demo "$@"
