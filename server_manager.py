"""
server_manager.py
-----------------
Quản lý nhiều socket server đồng thời, mỗi server phục vụ 1 loại cert.

Mỗi server cert được Root CA (issuer của ServerManager) ký, không còn
self-signed. Mô hình tin cậy:

    Root CA  ──ký──► Server cert  (issuer = Root CA subject)
    Client  ──verify chữ ký bằng Root CA public key trong Trust Store──►

Flavors:
  valid            – cert hợp lệ, Root CA ký đúng
  expired          – cert đã hết hạn (backdate)
  revoked_both     – revoked trong cả OCSP DB lẫn CRL (publish ngay)
  revoked_ocsp_only– chỉ có trong OCSP DB, CRL chưa cập nhật
  tampered         – cert bị lật 1 bit sau khi Root CA ký → chữ ký sai
"""

import os
import socket
import threading

from cert_generator import (
    generate_rsa_keypair,
    create_server_cert_signed_by_ca,
    save_cert_and_key,
    tamper_cert_pem,
)
from crl_manager import (
    revoke_serial_ocsp_only,
    build_and_publish_crl,
    unrevoke_serial,
)

FLAVORS = ("valid", "expired", "revoked_both", "revoked_ocsp_only", "tampered")


class ServerEntry:
    """Thông tin của 1 server instance đang chạy."""
    def __init__(self, name, port, flavor, serial, cert_path, key_path):
        self.name      = name
        self.port      = port
        self.flavor    = flavor
        self.serial    = serial
        self.cert_path = cert_path   # file cert PEM (có thể đã tamper)
        self.key_path  = key_path
        self.sock      = None        # server socket
        self.stop_flag = None        # {"stop": bool}


class ServerManager:
    """
    Quản lý dict các ServerEntry đang chạy.
    Mỗi entry có socket server riêng nghe trên port riêng.
    """

    def __init__(
        self,
        cert_dir: str,
        ocsp_db_path: str,
        crl_path: str,
        issuer_cert,
        issuer_key,
        ocsp_url: str = "http://localhost:8888/ocsp",
        crl_url: str  = "http://localhost:8889/crl.pem",
        log_callback=None,
    ):
        self.cert_dir     = cert_dir
        self.ocsp_db_path = ocsp_db_path
        self.crl_path     = crl_path
        self.issuer_cert  = issuer_cert
        self.issuer_key   = issuer_key
        self.ocsp_url     = ocsp_url
        self.crl_url      = crl_url
        self.log_callback = log_callback
        self.servers: dict[str, ServerEntry] = {}
        os.makedirs(cert_dir, exist_ok=True)

    def _log(self, msg: str):
        if self.log_callback:
            self.log_callback(msg)

    # ── Thêm server ──────────────────────────────────────────────────────────

    def add_server(self, name: str, port: int, flavor: str) -> ServerEntry:
        """
        Sinh cert theo flavor, mở socket server trên port.
        Trả về ServerEntry. Ném ValueError nếu name/port trùng.
        """
        if flavor not in FLAVORS:
            raise ValueError(f"Flavor không hợp lệ: {flavor}. Chọn: {FLAVORS}")
        if name in self.servers:
            raise ValueError(f"Tên server '{name}' đã tồn tại.")
        for entry in self.servers.values():
            if entry.port == port:
                raise ValueError(f"Port {port} đã được dùng bởi server '{entry.name}'.")

        cert_path = os.path.join(self.cert_dir, f"{name}.crt")
        key_path  = os.path.join(self.cert_dir, f"{name}.key")

        # 1. Sinh cặp khóa rồi để Root CA ký server cert
        key = generate_rsa_keypair()
        expired = (flavor == "expired")
        cert, serial = create_server_cert_signed_by_ca(
            server_private_key=key,
            ca_cert=self.issuer_cert,
            ca_private_key=self.issuer_key,
            common_name="localhost",
            dns_names=["localhost", "127.0.0.1"],
            ocsp_url=self.ocsp_url,
            crl_url=self.crl_url,
            expired=expired,
        )
        save_cert_and_key(cert, key, cert_path, key_path)
        self._log(
            f"[ServerMgr] '{name}' — server cert đã được Root CA ký "
            f"(serial={serial:#x})"
        )

        # 2. Xử lý revocation theo flavor
        if flavor == "revoked_ocsp_only":
            # Chỉ thêm vào OCSP DB, CRL chưa cập nhật
            revoke_serial_ocsp_only(serial, self.ocsp_db_path)
            self._log(f"[ServerMgr] '{name}' — revoked trong OCSP DB (CRL chưa biết)")

        elif flavor == "revoked_both":
            # Thêm OCSP DB + publish CRL ngay lập tức
            revoke_serial_ocsp_only(serial, self.ocsp_db_path)
            build_and_publish_crl(
                self.issuer_cert, self.issuer_key,
                self.ocsp_db_path, self.crl_path,
            )
            self._log(f"[ServerMgr] '{name}' — revoked trong OCSP DB + CRL đã publish")

        # 3. Tamper cert nếu cần (lật 1 bit trong chữ ký)
        if flavor == "tampered":
            with open(cert_path, "rb") as f:
                original_pem = f.read()
            tampered_pem = tamper_cert_pem(original_pem)
            with open(cert_path, "wb") as f:
                f.write(tampered_pem)
            self._log(f"[ServerMgr] '{name}' — cert đã bị tamper (1 bit lật)")

        # 4. Tạo entry và khởi động socket server
        entry = ServerEntry(name, port, flavor, serial, cert_path, key_path)
        self._start_socket_server(entry)
        self.servers[name] = entry
        self._log(f"[ServerMgr] '{name}' — socket server sẵn sàng tại port {port}")
        return entry

    # ── Xóa server ───────────────────────────────────────────────────────────

    def remove_server(self, name: str):
        """Dừng socket server, xóa cert file, rollback revocation state."""
        entry = self.servers.pop(name, None)
        if entry is None:
            return

        # Dừng socket server
        if entry.stop_flag:
            entry.stop_flag["stop"] = True
        if entry.sock:
            try:
                entry.sock.close()
            except Exception:
                pass

        # Rollback revocation (xóa khỏi OCSP DB)
        if entry.flavor in ("revoked_both", "revoked_ocsp_only"):
            unrevoke_serial(entry.serial, self.ocsp_db_path)
            self._log(f"[ServerMgr] '{name}' — serial {entry.serial:#x} xóa khỏi OCSP DB")

        # Xóa cert files
        for path in (entry.cert_path, entry.key_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

        self._log(f"[ServerMgr] '{name}' đã xóa.")

    def remove_all(self):
        """Dừng tất cả server (dùng khi đóng ứng dụng)."""
        for name in list(self.servers.keys()):
            self.remove_server(name)

    # ── Socket server nội bộ ─────────────────────────────────────────────────

    def _start_socket_server(self, entry: ServerEntry):
        """Khởi động background thread lắng nghe socket cho entry."""
        try:
            srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv_sock.bind(("localhost", entry.port))
            srv_sock.listen(5)
            srv_sock.settimeout(1.0)
        except OSError as e:
            raise OSError(f"Không thể bind port {entry.port}: {e}") from e

        stop_flag = {"stop": False}
        entry.sock      = srv_sock
        entry.stop_flag = stop_flag

        def _serve():
            while not stop_flag["stop"]:
                try:
                    conn, addr = srv_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self._handle_conn,
                    args=(conn, addr, entry),
                    daemon=True,
                ).start()

        threading.Thread(target=_serve, daemon=True).start()

    def _handle_conn(self, conn, addr, entry: ServerEntry):
        """Xử lý một kết nối đến: phục vụ GET_CERT."""
        try:
            conn.settimeout(5.0)
            data = conn.recv(1024).decode(errors="ignore").strip()

            if data == "GET_CERT":
                with open(entry.cert_path, "rb") as f:
                    cert_pem = f.read()
                conn.sendall(len(cert_pem).to_bytes(4, "big"))
                conn.sendall(cert_pem)
                self._log(
                    f"[{entry.name}:{entry.port}] Gửi cert "
                    f"({len(cert_pem)} B) → {addr}"
                )
            else:
                self._log(f"[{entry.name}:{entry.port}] Request lạ: {data!r}")
        except Exception as e:
            self._log(f"[{entry.name}:{entry.port}] Lỗi: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
