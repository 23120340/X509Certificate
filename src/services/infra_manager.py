"""
services/infra_manager.py
-------------------------
Quản lý vòng đời 2 cặp CRL+OCSP HTTP server: Prod và Lab.

- Prod servers (port 8889/8888): auto-start khi app khởi động. Phục vụ cert
  thật phát hành từ DB (issued_certs + revoked_at), backed by certs/crl.pem
  + certs/ocsp_db.json. Customer B.9 verify external cert dựa vào 2 server này.
- Lab servers (port 9889/9888): khởi động thủ công khi user mở Verification
  Lab. Phục vụ demo cert (Server-A/B/C/D/E), backed by lab/crl.pem +
  lab/ocsp_db.json. Tách hoàn toàn khỏi prod để demo data không gây nhiễu.

Idempotent: gọi start_*() nhiều lần chỉ start 1 lần. Lab có thể stop riêng
khi đóng Verification Lab; Prod chạy suốt đời app process.

Toggle OCSP enabled qua state dict (mutable reference) — cho phép UI bật/tắt
runtime mà không cần restart server.
"""

import logging
import os

from infra.crl_server import start_crl_server
from infra.ocsp_server import start_ocsp_server

_log = logging.getLogger("x509ca.infra")


# ── Default ports + paths ─────────────────────────────────────────────────────
# Cho phép override qua env để tránh port conflict trên máy user.

PROD_CRL_PORT  = int(os.environ.get("PROD_CRL_PORT",  "8889"))
PROD_OCSP_PORT = int(os.environ.get("PROD_OCSP_PORT", "8888"))
LAB_CRL_PORT   = int(os.environ.get("LAB_CRL_PORT",   "9889"))
LAB_OCSP_PORT  = int(os.environ.get("LAB_OCSP_PORT",  "9888"))

# Re-export path constants từ config.py — alias để code cũ không phải đổi.
from config import (
    PROD_CRL_PATH, PROD_OCSP_DB_PATH as PROD_OCSP_DB,
    LAB_CRL_PATH, LAB_OCSP_DB_PATH as LAB_OCSP_DB,
    CERTS_DIR, LAB_DIR,
)


def prod_crl_url() -> str:
    return f"http://localhost:{PROD_CRL_PORT}/crl.pem"


def prod_ocsp_url() -> str:
    return f"http://localhost:{PROD_OCSP_PORT}/ocsp"


def lab_crl_url() -> str:
    return f"http://localhost:{LAB_CRL_PORT}/crl.pem"


def lab_ocsp_url() -> str:
    return f"http://localhost:{LAB_OCSP_PORT}/ocsp"


class InfraManager:
    """Singleton quản lý prod + lab servers cho cả app process.

    Lifecycle:
        boot → start_prod_servers() (auto, in ui/app.py)
        Lab open → start_lab_servers()
        Lab close → stop_lab_servers()
        app exit → stop_all()
    """

    def __init__(self):
        # HTTPServer instances — None nếu chưa start
        self._prod_crl  = None
        self._prod_ocsp = None
        self._lab_crl   = None
        self._lab_ocsp  = None

        # OCSP enabled state dicts (mutable, share với handler closure)
        self._prod_ocsp_state = None
        self._lab_ocsp_state  = None

        # Log callbacks — set bởi caller (Lab UI muốn forward log ra Tk widget)
        self._lab_log_cb = None

    # ── Prod ────────────────────────────────────────────────────────────────

    def start_prod_servers(self):
        """Idempotent. Auto-create thư mục certs/ nếu chưa có."""
        os.makedirs(CERTS_DIR, exist_ok=True)

        if self._prod_crl is None:
            try:
                self._prod_crl = start_crl_server(
                    host="localhost", port=PROD_CRL_PORT,
                    crl_path=PROD_CRL_PATH,
                )
                _log.info("Prod CRL server started → %s", prod_crl_url())
            except OSError as e:
                _log.warning("Prod CRL server không start được (port %d?): %s",
                             PROD_CRL_PORT, e)

        if self._prod_ocsp is None:
            try:
                self._prod_ocsp, self._prod_ocsp_state = start_ocsp_server(
                    host="localhost", port=PROD_OCSP_PORT,
                    revoked_list_path=PROD_OCSP_DB,
                )
                _log.info("Prod OCSP server started → %s", prod_ocsp_url())
            except OSError as e:
                _log.warning("Prod OCSP server không start được (port %d?): %s",
                             PROD_OCSP_PORT, e)

    def stop_prod_servers(self):
        """Shutdown prod servers — gọi khi app exit."""
        if self._prod_crl is not None:
            try:
                self._prod_crl.shutdown()
                self._prod_crl.server_close()
            except Exception:
                pass
            self._prod_crl = None
        if self._prod_ocsp is not None:
            try:
                self._prod_ocsp.shutdown()
                self._prod_ocsp.server_close()
            except Exception:
                pass
            self._prod_ocsp = None
            self._prod_ocsp_state = None

    # ── Lab ─────────────────────────────────────────────────────────────────

    def start_lab_servers(self, log_callback=None):
        """Start lab CRL+OCSP. log_callback forward log ra Lab UI."""
        os.makedirs(LAB_DIR, exist_ok=True)
        self._lab_log_cb = log_callback

        if self._lab_crl is None:
            try:
                self._lab_crl = start_crl_server(
                    host="localhost", port=LAB_CRL_PORT,
                    crl_path=LAB_CRL_PATH, log_callback=log_callback,
                )
                _log.info("Lab CRL server started → %s", lab_crl_url())
            except OSError as e:
                _log.warning("Lab CRL server không start được (port %d?): %s",
                             LAB_CRL_PORT, e)
                raise

        if self._lab_ocsp is None:
            try:
                self._lab_ocsp, self._lab_ocsp_state = start_ocsp_server(
                    host="localhost", port=LAB_OCSP_PORT,
                    revoked_list_path=LAB_OCSP_DB, log_callback=log_callback,
                )
                _log.info("Lab OCSP server started → %s", lab_ocsp_url())
            except OSError as e:
                _log.warning("Lab OCSP server không start được (port %d?): %s",
                             LAB_OCSP_PORT, e)
                raise

    def stop_lab_servers(self):
        """Shutdown lab servers — gọi khi Lab UI đóng."""
        if self._lab_crl is not None:
            try:
                self._lab_crl.shutdown()
                self._lab_crl.server_close()
            except Exception:
                pass
            self._lab_crl = None
        if self._lab_ocsp is not None:
            try:
                self._lab_ocsp.shutdown()
                self._lab_ocsp.server_close()
            except Exception:
                pass
            self._lab_ocsp = None
            self._lab_ocsp_state = None

    def set_lab_ocsp_enabled(self, enabled: bool):
        """Toggle Lab OCSP responder enabled/503 runtime."""
        if self._lab_ocsp_state is not None:
            self._lab_ocsp_state["enabled"] = enabled

    def set_prod_ocsp_enabled(self, enabled: bool):
        """Toggle Prod OCSP responder (hiếm khi cần — chủ yếu cho test)."""
        if self._prod_ocsp_state is not None:
            self._prod_ocsp_state["enabled"] = enabled

    # ── Public state queries ────────────────────────────────────────────────

    def is_prod_running(self) -> bool:
        """True nếu cả 2 prod server (CRL + OCSP) đều đang chạy."""
        return self._prod_crl is not None and self._prod_ocsp is not None

    def is_lab_running(self) -> bool:
        """True nếu cả 2 lab server (CRL + OCSP) đều đang chạy."""
        return self._lab_crl is not None and self._lab_ocsp is not None

    def get_lab_ocsp_state(self) -> "dict | None":
        """Trả về OCSP state dict của Lab (mutable reference) hoặc None.

        Cho phép Lab UI bind 1 BooleanVar Tk vào field 'enabled' để toggle
        runtime mà không gọi method qua manager. Trả None nếu Lab chưa start.
        """
        return self._lab_ocsp_state

    # ── Status ──────────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Trả về trạng thái cả 4 server cho UI hiển thị badge."""
        return {
            "prod_crl":  self._prod_crl  is not None,
            "prod_ocsp": self._prod_ocsp is not None,
            "lab_crl":   self._lab_crl   is not None,
            "lab_ocsp":  self._lab_ocsp  is not None,
        }

    def stop_all(self):
        self.stop_lab_servers()
        self.stop_prod_servers()


# ── Module-level singleton ────────────────────────────────────────────────────

_instance: InfraManager = None


def get_infra() -> InfraManager:
    """Lazy singleton — gọi lần đầu tạo instance, lần sau trả instance cũ."""
    global _instance
    if _instance is None:
        _instance = InfraManager()
    return _instance
