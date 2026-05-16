"""
legacy/server_manager.py
------------------------
Quản lý nhiều socket server đồng thời, mỗi server phục vụ 1 loại cert.

Mỗi server cert được Root CA (issuer của ServerManager) ký, không còn
self-signed. Mô hình tin cậy:

    Root CA  ──ký──► Server cert  (issuer = Root CA subject)
    Client  ──verify chữ ký bằng Root CA public key trong Trust Store──►

Mô hình trạng thái (mỗi server có 3 trục độc lập):
  lifecycle         – trạng thái pháp lý của cert
                      • valid    – còn trong thời hạn, chưa revoke
                      • expired  – đã quá Not After
                      • revoked  – đã có trong CRL/OCSP DB
  revocation_scope  – chỉ áp dụng khi lifecycle=revoked
                      • none, ocsp_only, both
  wire_mutation     – mutation áp lên blob khi server gửi cho client
                      • none, tampered

`flavor` là "trạng thái khởi tạo" (immutable, set một lần ở add_server),
còn `lifecycle/revocation_scope/wire_mutation` là trạng thái runtime
(mutable, có thể đổi qua các method state-transition như renew_server).

Flavors → state ban đầu:
  valid              → (valid,   none,      none)
  expired            → (expired, none,      none)
  revoked_both       → (revoked, both,      none)
  revoked_ocsp_only  → (revoked, ocsp_only, none)
  tampered           → (valid,   none,      tampered)
"""

import os
import socket
import threading
from datetime import datetime, timezone

from core.cert_builder import (
    generate_rsa_keypair,
    create_server_cert_signed_by_ca,
    save_cert_and_key,
    tamper_cert_pem,
    load_cert,
    load_private_key,
)
from core.crl import (
    revoke_serial_ocsp_only,
    build_and_publish_crl,
    unrevoke_serial,
)

FLAVORS = ("valid", "expired", "revoked_both", "revoked_ocsp_only", "tampered")

# Trục trạng thái runtime
LIFECYCLE_STATES   = ("valid", "expired", "revoked")
REVOCATION_SCOPES  = ("none", "ocsp_only", "both")
WIRE_MUTATIONS     = ("none", "tampered")

# Mapping flavor (state khởi tạo) → (lifecycle, revocation_scope, wire_mutation)
FLAVOR_TO_STATE = {
    "valid":             ("valid",   "none",      "none"),
    "expired":           ("expired", "none",      "none"),
    "revoked_both":      ("revoked", "both",      "none"),
    "revoked_ocsp_only": ("revoked", "ocsp_only", "none"),
    "tampered":          ("valid",   "none",      "tampered"),
}

# Ngưỡng "chuẩn bị hết hạn" mặc định cho is_renewal_due
DEFAULT_RENEWAL_THRESHOLD_SECONDS = 30 * 86400  # 30 ngày


class ServerEntry:
    """Thông tin của 1 server instance đang chạy.

    `flavor` là state khởi tạo (immutable). Trạng thái runtime hiện tại nằm
    ở `lifecycle / revocation_scope / wire_mutation` — các method state-
    transition (vd: `renew_server`) sửa các field này, KHÔNG sửa `flavor`.

    `previous_serials` ghi lại serial của những cert đã bị thay thế qua các
    lần renew, dùng cho audit ("server này từng có serial X, đã rotate sang Y").
    """
    def __init__(self, name, port, flavor, serial, cert_path, key_path):
        self.name      = name
        self.port      = port
        self.flavor    = flavor              # initial flavor (immutable)
        self.serial    = serial              # serial của cert hiện đang serve
        self.cert_path = cert_path           # file cert PEM (có thể đã tamper)
        self.key_path  = key_path
        self.sock      = None                # server socket
        self.stop_flag = None                # {"stop": bool}

        # Trạng thái runtime (mutable). Khởi tạo từ flavor.
        lifecycle, scope, mutation = FLAVOR_TO_STATE[flavor]
        self.lifecycle: str        = lifecycle
        self.revocation_scope: str = scope
        self.wire_mutation: str    = mutation

        # Audit: serial của các cert đã bị thay thế qua renew (oldest → newest)
        self.previous_serials: list[int] = []


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

    # ── Reuse cert đã lưu (chỉ dùng cho flavor 'valid') ──────────────────────

    def _try_reuse_valid_cert(self, name: str, cert_path: str, key_path: str):
        """
        Thử load cert/key đã có trên disk cho flavor 'valid'.

        Reuse được khi: file tồn tại, parse được, issuer khớp Root CA hiện tại,
        và cert còn trong thời hạn. Mục đích: pin warning ổn định qua các lần
        khởi động lại GUI (cùng tên server → cùng fingerprint → pin match).

        Trả về (cert, key, serial) nếu reuse được, None nếu cần sinh mới.
        """
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            return None
        try:
            cert = load_cert(cert_path)
            key = load_private_key(key_path)
        except Exception as e:
            self._log(
                f"[ServerMgr] '{name}' — không load được cert/key cũ ({e}); sinh mới"
            )
            return None

        if cert.issuer != self.issuer_cert.subject:
            self._log(
                f"[ServerMgr] '{name}' — cert cũ có issuer khác Root CA hiện tại; sinh mới"
            )
            return None

        try:
            na = cert.not_valid_after_utc
        except AttributeError:
            na = cert.not_valid_after.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= na:
            self._log(f"[ServerMgr] '{name}' — cert cũ đã hết hạn; sinh mới")
            return None

        return cert, key, cert.serial_number

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

        # 1. Sinh cert (hoặc reuse với flavor 'valid' nếu file cũ còn dùng được)
        reused = None
        if flavor == "valid":
            reused = self._try_reuse_valid_cert(name, cert_path, key_path)

        if reused is not None:
            cert, key, serial = reused
            self._log(
                f"[ServerMgr] '{name}' — REUSE cert/key trên disk "
                f"(serial={serial:#x}); pin sẽ ổn định qua các lần Thêm Server"
            )
        else:
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

    def remove_server(self, name: str, cleanup_files: bool = True):
        """
        Dừng socket server. Nếu `cleanup_files=True` (mặc định, dùng khi user
        bấm Xóa): xóa cert file + rollback revocation. Nếu `False` (dùng khi
        app đóng): chỉ stop socket, giữ nguyên file để lần khởi động sau
        có thể reuse (xem `_try_reuse_valid_cert`).
        """
        entry = self.servers.pop(name, None)
        if entry is None:
            return

        # Luôn luôn dừng socket server
        if entry.stop_flag:
            entry.stop_flag["stop"] = True
        if entry.sock:
            try:
                entry.sock.close()
            except Exception:
                pass

        if not cleanup_files:
            self._log(f"[ServerMgr] '{name}' — socket dừng, giữ file cho lần sau")
            return

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

    def remove_all(self, cleanup_files: bool = True):
        """
        Dừng tất cả server. `cleanup_files=False` khi đóng app → giữ file để
        lần sau reuse.
        """
        for name in list(self.servers.keys()):
            self.remove_server(name, cleanup_files=cleanup_files)

    # ── Renew / lifecycle transition ─────────────────────────────────────────

    def is_renewal_due(
        self,
        name: str,
        threshold_seconds: float = DEFAULT_RENEWAL_THRESHOLD_SECONDS,
    ) -> bool:
        """
        Trả về True nếu cert hiện tại của server `name` còn lại < threshold
        thời gian, hoặc đã hết hạn (lifecycle=expired). Dùng để bật/disable
        nút Renew trên GUI hoặc làm trigger cho auto-renew job.

        Trả về False nếu server không tồn tại, không load được cert, hay
        wire_mutation=tampered (cert đã hỏng, không phải bài toán renew).
        """
        entry = self.servers.get(name)
        if entry is None:
            return False
        if entry.wire_mutation == "tampered":
            return False
        try:
            cert = load_cert(entry.cert_path)
        except Exception:
            return False
        try:
            na = cert.not_valid_after_utc
        except AttributeError:
            na = cert.not_valid_after.replace(tzinfo=timezone.utc)
        remaining = (na - datetime.now(timezone.utc)).total_seconds()
        return remaining < threshold_seconds

    def renew_server(
        self,
        name: str,
        rotate_key: bool = True,
        validity_days: int = 365,
    ) -> "ServerEntry":
        """
        Sinh cert MỚI (Root CA ký, không expired), ghi đè file cert/key của
        server đang chạy. Socket vẫn giữ — lần GET_CERT kế tiếp client nhận
        được cert mới, fingerprint sẽ khác → client-side pin store xử lý
        rotation (xem `check_pinned` trong client.py).

        Tham số:
          rotate_key=True   → sinh keypair MỚI (best-practice, mặc định)
                              False → tái dùng key cũ (chỉ rotate cert).
          validity_days     → thời hạn cert mới (mặc định 365).

        Ràng buộc:
          - Không renew khi wire_mutation=tampered (cần untamper trước —
            chưa implement, raise ValueError).
          - Chưa implement renew cho lifecycle=revoked (cần unrevoke trước —
            chưa implement, raise NotImplementedError).

        Trả về ServerEntry đã cập nhật. Sau khi gọi:
          entry.lifecycle = "valid"
          entry.serial    = serial mới
          entry.previous_serials += [serial cũ]
          entry.flavor    GIỮ NGUYÊN (đại diện initial state)
        """
        entry = self.servers.get(name)
        if entry is None:
            raise ValueError(f"Server '{name}' không tồn tại.")
        if entry.wire_mutation == "tampered":
            raise ValueError(
                f"Server '{name}' đang ở wire_mutation=tampered — renew không "
                f"có ý nghĩa cho cert đã bị giả mạo. Untamper trước."
            )
        if entry.lifecycle == "revoked":
            raise NotImplementedError(
                f"Server '{name}' đang lifecycle=revoked — renew flow cho "
                f"revoked chưa làm. Cần unrevoke trước (chưa implement)."
            )

        old_serial = entry.serial

        # 1. Key: rotate (mới) hoặc giữ key cũ
        if rotate_key:
            key = generate_rsa_keypair()
        else:
            try:
                key = load_private_key(entry.key_path)
            except Exception as e:
                raise RuntimeError(
                    f"Không load được key cũ tại {entry.key_path}: {e}"
                ) from e

        # 2. Sinh cert mới (KHÔNG expired), ký bởi Root CA
        cert, new_serial = create_server_cert_signed_by_ca(
            server_private_key=key,
            ca_cert=self.issuer_cert,
            ca_private_key=self.issuer_key,
            common_name="localhost",
            dns_names=["localhost", "127.0.0.1"],
            ocsp_url=self.ocsp_url,
            crl_url=self.crl_url,
            validity_days=validity_days,
            expired=False,
        )

        # 3. Ghi đè file. Nếu không rotate key thì cũng ghi đè lại key cho
        #    tường minh — load_private_key trả về cùng object thôi.
        save_cert_and_key(cert, key, entry.cert_path, entry.key_path)

        # 4. Cập nhật runtime state. Lưu ý: KHÔNG đổi entry.flavor.
        entry.previous_serials.append(old_serial)
        entry.serial    = new_serial
        entry.lifecycle = "valid"

        self._log(
            f"[ServerMgr] '{name}' — RENEW thành công "
            f"({'rotate key' if rotate_key else 'giữ key cũ'}); "
            f"serial cũ={old_serial:#x} → mới={new_serial:#x}; "
            f"hiệu lực {validity_days} ngày. "
            f"Client sẽ thấy fingerprint khác lần GET_CERT tiếp theo."
        )
        return entry

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
