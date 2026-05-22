"""
infra/ocsp_server.py
--------------------
OCSP Responder đơn giản qua HTTP GET.

Endpoint: GET /ocsp?serial=<int>
Response: {"serial": "...", "status": "GOOD" | "REVOKED"}

Factory pattern: mỗi instance có closure-bound `revoked_list_path` + `enabled`
flag riêng (thông qua mutable dict). Cho phép chạy nhiều OCSP server song song
(prod + lab) trên port khác nhau, mỗi cái tham chiếu DB khác nhau.

`enabled` flag wrap trong dict để Lab UI có thể toggle runtime (giả lập OCSP
down) qua reference handle trả về.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from core.crl import load_revoked_list


def _make_ocsp_handler(revoked_list_path: str, state: dict, log_callback=None):
    """Tạo Handler class với path + state capture qua closure.

    state: {"enabled": bool} — mutable, cho phép toggle runtime.
    """

    class OCSPHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if not state.get("enabled", True):
                body = b'{"error": "OCSP responder temporarily unavailable"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                if log_callback:
                    log_callback("[OCSP] Responder DISABLED — trả 503")
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

            revoked = load_revoked_list(revoked_list_path)
            status = "REVOKED" if serial_int in revoked else "GOOD"

            if log_callback:
                log_callback(f"[OCSP] serial={serial_int} → {status}")

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

    return OCSPHandler


def start_ocsp_server(
    host: str = "localhost",
    port: int = 8888,
    revoked_list_path: str = "certs/ocsp_db.json",
    log_callback=None,
):
    """Khởi động OCSP server ở background thread.

    Returns: (HTTPServer instance, state_dict).
      state_dict["enabled"] = True/False để toggle runtime — caller giữ ref
      mutable này để bật/tắt giả lập OCSP down từ UI.
    """
    state = {"enabled": True}
    handler_cls = _make_ocsp_handler(revoked_list_path, state, log_callback)

    # ThreadingHTTPServer: mỗi request 1 thread con — chống slowloris + cho
    # phép concurrent verify từ nhiều client mà không serial hóa.
    server = ThreadingHTTPServer((host, port), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if log_callback:
        log_callback(f"[OCSP] Server started at http://{host}:{port}/ocsp")
    return server, state
