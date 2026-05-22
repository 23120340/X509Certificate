"""
infra/crl_server.py
-------------------
HTTP server đơn giản để phát file CRL (để Client tải về và đối chiếu),
tương ứng với URL được nhúng trong CRL Distribution Points extension.

Factory pattern: mỗi gọi `start_crl_server` tạo Handler class riêng, capture
`crl_path` qua closure. Cho phép chạy nhiều instance song song (prod + lab)
trên port khác nhau, mỗi instance serve file CRL khác nhau.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _make_crl_handler(crl_path: str, log_callback=None):
    """Tạo Handler class với crl_path + log_callback capture qua closure."""

    class CRLHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ("/crl.pem", "/crl"):
                self.send_response(404)
                self.end_headers()
                return

            if not os.path.exists(crl_path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"CRL not found")
                return

            with open(crl_path, "rb") as f:
                data = f.read()

            if log_callback:
                log_callback(f"[CRL]  Client tải CRL ({len(data)} bytes)")

            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            return

    return CRLHandler


def start_crl_server(
    host: str = "localhost",
    port: int = 8889,
    crl_path: str = "certs/crl.pem",
    log_callback=None,
):
    """Khởi động CRL server background thread.

    Returns: HTTPServer instance — caller giữ ref để shutdown().
    """
    handler_cls = _make_crl_handler(crl_path, log_callback)
    # ThreadingHTTPServer: mỗi request 1 thread con — không block khi nhiều
    # client verify cùng lúc, và 1 slow client không treo các client khác.
    server = ThreadingHTTPServer((host, port), handler_cls)
    server.daemon_threads = True  # thread con tự exit khi main process kết thúc
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if log_callback:
        log_callback(f"[CRL]  Server started at http://{host}:{port}/crl.pem")
    return server
