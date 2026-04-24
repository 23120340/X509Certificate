"""
ocsp_server.py
--------------
Phần 5 của đề bài: Dịch vụ OCSP kiểm tra trạng thái chứng chỉ qua HTTP đơn giản.

Endpoint:
    GET /ocsp?serial=<serial_number>

Response (JSON):
    {"serial": "...", "status": "GOOD"}    -> Chứng chỉ hợp lệ
    {"serial": "...", "status": "REVOKED"} -> Chứng chỉ đã bị thu hồi
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from crl_manager import load_revoked_list


class OCSPHandler(BaseHTTPRequestHandler):
    # Đường dẫn file revoked list - được set từ start_ocsp_server
    revoked_list_path = "certs/revoked_serials.json"
    log_callback = None

    def do_GET(self):
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
            OCSPHandler.log_callback(
                f"[OCSP] Query serial={serial_int} -> {status}"
            )

        self._json(200, {"serial": str(serial_int), "status": status})

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress default stderr logging
        return


def start_ocsp_server(
    host: str = "localhost",
    port: int = 8888,
    revoked_list_path: str = "certs/revoked_serials.json",
    log_callback=None,
):
    """Khởi động OCSP server ở background thread, trả về instance HTTPServer."""
    OCSPHandler.revoked_list_path = revoked_list_path
    OCSPHandler.log_callback = log_callback

    server = HTTPServer((host, port), OCSPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if log_callback:
        log_callback(f"[OCSP] Server started at http://{host}:{port}/ocsp")
    return server
