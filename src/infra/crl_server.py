"""
infra/crl_server.py
-------------------
HTTP server đơn giản để phát file CRL (để Client tải về và đối chiếu),
tương ứng với URL được nhúng trong CRL Distribution Points extension.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class CRLHandler(BaseHTTPRequestHandler):
    crl_path = "certs/crl.pem"
    log_callback = None

    def do_GET(self):
        # Chỉ phục vụ đúng 1 endpoint /crl.pem
        if self.path not in ("/crl.pem", "/crl"):
            self.send_response(404)
            self.end_headers()
            return

        if not os.path.exists(CRLHandler.crl_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"CRL not found")
            return

        with open(CRLHandler.crl_path, "rb") as f:
            data = f.read()

        if CRLHandler.log_callback:
            CRLHandler.log_callback(
                f"[CRL]  Client tải CRL ({len(data)} bytes)"
            )

        self.send_response(200)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        return


def start_crl_server(
    host: str = "localhost",
    port: int = 8889,
    crl_path: str = "certs/crl.pem",
    log_callback=None,
):
    CRLHandler.crl_path = crl_path
    CRLHandler.log_callback = log_callback

    server = HTTPServer((host, port), CRLHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if log_callback:
        log_callback(f"[CRL]  Server started at http://{host}:{port}/crl.pem")
    return server
