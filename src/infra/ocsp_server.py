"""
infra/ocsp_server.py
--------------------
OCSP Responder đơn giản qua HTTP GET.

Endpoint: GET /ocsp?serial=<int>
Response: {"serial": "...", "status": "GOOD" | "REVOKED"}

Khi OCSPHandler.enabled = False, server trả 503 để mô phỏng OCSP down.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from core.crl import load_revoked_list


class OCSPHandler(BaseHTTPRequestHandler):
    revoked_list_path = "certs/ocsp_db.json"
    log_callback = None
    enabled = True          # False → giả lập OCSP responder bị tắt / lỗi mạng

    def do_GET(self):
        # Mô phỏng OCSP down khi disabled
        if not OCSPHandler.enabled:
            body = b'{"error": "OCSP responder temporarily unavailable"}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if OCSPHandler.log_callback:
                OCSPHandler.log_callback("[OCSP] Responder DISABLED — trả 503")
            return

        parsed = urlparse(self.path)
        if parsed.path != "/ocsp":
            self.send_response(404)
            self.end_headers()
            return

        query = parse_qs(parsed.query)
        serial_raw = query.get("serial", [None])[0]
        if serial_raw is None:
            self._json(400, {"error": "missing 'serial' parameter"})
            return

        try:
            serial_int = int(serial_raw)
        except ValueError:
            self._json(400, {"error": "invalid serial"})
            return

        revoked = load_revoked_list(OCSPHandler.revoked_list_path)
        status = "REVOKED" if serial_int in revoked else "GOOD"

        if OCSPHandler.log_callback:
            OCSPHandler.log_callback(f"[OCSP] serial={serial_int} → {status}")

        self._json(200, {"serial": str(serial_int), "status": status})

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def start_ocsp_server(
    host: str = "localhost",
    port: int = 8888,
    revoked_list_path: str = "certs/ocsp_db.json",
    log_callback=None,
):
    """Khởi động OCSP server ở background thread. Trả về HTTPServer instance."""
    OCSPHandler.revoked_list_path = revoked_list_path
    OCSPHandler.log_callback = log_callback

    server = HTTPServer((host, port), OCSPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if log_callback:
        log_callback(f"[OCSP] Server started at http://{host}:{port}/ocsp")
    return server
