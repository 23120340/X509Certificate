"""
infra/csr_api_server.py
-----------------------
Small HTTP API for the LAN CSR demo.

Machine A runs the Admin app and starts this server. Machine B posts a CSR to
`/api/csr/submit`; the request appears in the normal Admin CSR Queue.
"""

import json
import os
import threading
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer

from services.remote_csr import (
    submit_remote_csr,
    list_remote_csrs,
    get_remote_csr_detail,
    list_remote_certs,
    get_remote_cert_detail,
    submit_remote_revocation_request,
    list_remote_revocation_requests,
    RemoteCSRError,
)
from services.crl_publish import (
    DEFAULT_CRL_PATH,
    get_published_crl_info,
    list_crl_entries,
)


CSR_API_HOST = os.environ.get("X509_CSR_API_HOST", "0.0.0.0")
CSR_API_PORT = int(os.environ.get("X509_CSR_API_PORT", "8787"))
CSR_API_TOKEN = os.environ.get("X509_CSR_API_TOKEN", "")


def _is_loopback_bind(host: str) -> bool:
    host = (host or "").strip().lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def start_csr_api_server(
    *,
    db_path: str,
    host: str = CSR_API_HOST,
    port: int = CSR_API_PORT,
    token: str = CSR_API_TOKEN,
    log_callback=None,
) -> HTTPServer:
    """Start the LAN CSR API in a background thread."""
    if not token and not _is_loopback_bind(host):
        raise ValueError(
            "CSR API token is required when binding to a LAN/public address."
        )

    class Handler(BaseHTTPRequestHandler):
        server_version = "X509CSRAPI/1.0"

        def log_message(self, fmt, *args):
            if log_callback:
                log_callback("[CSR API] " + fmt % args)

        def _send_json(self, status: int, payload: dict):
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if not token:
                return True
            return self.headers.get("X-CSR-API-Token") == token

        def do_GET(self):
            if self.path == "/health":
                self._send_json(200, {"ok": True, "service": "csr-api"})
                return
            self._send_json(404, {"ok": False, "error": "not found"})

        def _read_json_payload(self) -> dict:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 512 * 1024:
                raise RemoteCSRError("invalid request size")
            return json.loads(self.rfile.read(size).decode("utf-8"))

        def do_POST(self):
            if not self._authorized():
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return
            try:
                payload = self._read_json_payload()
                if self.path == "/api/csr/submit":
                    rec = submit_remote_csr(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        key_name=payload.get("key_name", "remote-key"),
                        csr_pem=payload.get("csr_pem", ""),
                        db_path=db_path,
                    )
                    self._send_json(201, {"ok": True, "csr": rec})
                    return
                if self.path == "/api/customer/csrs":
                    rows = list_remote_csrs(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        status=payload.get("status") or None,
                        db_path=db_path,
                    )
                    self._send_json(200, {"ok": True, "csrs": rows})
                    return
                if self.path == "/api/customer/csr/detail":
                    rec = get_remote_csr_detail(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        csr_id=int(payload.get("csr_id", 0)),
                        db_path=db_path,
                    )
                    if rec is None:
                        self._send_json(404, {"ok": False, "error": "CSR not found"})
                    else:
                        self._send_json(200, {"ok": True, "csr": rec})
                    return
                if self.path == "/api/customer/certs":
                    rows = list_remote_certs(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        status=payload.get("status") or None,
                        db_path=db_path,
                    )
                    self._send_json(200, {"ok": True, "certs": rows})
                    return
                if self.path == "/api/customer/cert/detail":
                    rec = get_remote_cert_detail(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        cert_id=int(payload.get("cert_id", 0)),
                        db_path=db_path,
                    )
                    if rec is None:
                        self._send_json(404, {"ok": False, "error": "cert not found"})
                    else:
                        self._send_json(200, {"ok": True, "cert": rec})
                    return
                if self.path == "/api/customer/revoke/submit":
                    rec = submit_remote_revocation_request(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        cert_id=int(payload.get("cert_id", 0)),
                        reason=payload.get("reason", ""),
                        key_compromise=bool(payload.get("key_compromise", False)),
                        db_path=db_path,
                    )
                    self._send_json(201, {"ok": True, "revocation_request": rec})
                    return
                if self.path == "/api/customer/revoke/requests":
                    rows = list_remote_revocation_requests(
                        username=payload.get("username", ""),
                        password=payload.get("password", ""),
                        db_path=db_path,
                    )
                    self._send_json(200, {"ok": True, "revocation_requests": rows})
                    return
                if self.path == "/api/crl/current":
                    info = get_published_crl_info(DEFAULT_CRL_PATH)
                    entries = list_crl_entries(DEFAULT_CRL_PATH, db_path=db_path)
                    self._send_json(
                        200,
                        {"ok": True, "crl_info": info, "crl_entries": entries},
                    )
                    return
            except json.JSONDecodeError:
                self._send_json(400, {"ok": False, "error": "invalid JSON"})
                return
            except (TypeError, ValueError):
                self._send_json(400, {"ok": False, "error": "invalid id"})
                return
            except RemoteCSRError as e:
                self._send_json(400, {"ok": False, "error": str(e)})
                return
            except Exception as e:
                self._send_json(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})
                return
            self._send_json(404, {"ok": False, "error": "not found"})

    server = HTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if log_callback:
        log_callback(f"[CSR API] listening on {host}:{port}")
    return server
