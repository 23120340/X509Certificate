"""
ra.py
-----
Registration Authority (RA).

RA không có quyền ký certificate. Nhiệm vụ của RA:
  1. Xác thực tính hợp lệ của CSR (chữ ký, thông tin subject).
  2. Chuyển CSR đã xác thực đến CA Root để ký.
  3. Trả certificate đã ký về cho bên yêu cầu (server).
"""

from cryptography import x509
from cryptography.x509.oid import NameOID

from cert_generator import ca_sign_csr


def validate_csr(csr) -> tuple:
    """Kiểm tra CSR: chữ ký hợp lệ và có CN. Trả về (ok: bool, message: str)."""
    if not csr.is_signature_valid:
        return False, "Chữ ký CSR không hợp lệ — yêu cầu bị từ chối"

    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or not cn_attrs[0].value:
        return False, "CSR thiếu Common Name (CN) — yêu cầu bị từ chối"

    return True, f"CSR hợp lệ (CN={cn_attrs[0].value})"


def process_request(
    csr,
    ca_cert,
    ca_key,
    ocsp_url: str = "http://localhost:8888/ocsp",
    crl_url: str = "http://localhost:8889/crl.pem",
    validity_days: int = 365,
    expired: bool = False,
    log_callback=None,
) -> tuple:
    """
    RA xác thực CSR rồi chuyển cho CA Root ký.
    Trả về (certificate, serial_number).
    """
    def log(msg):
        if log_callback:
            log_callback(msg)

    log("[RA] Nhận CSR từ Server, tiến hành xác thực...")

    ok, msg = validate_csr(csr)
    if not ok:
        raise ValueError(msg)
    log(f"[RA] {msg}")

    log("[RA] Chuyển CSR đã xác thực → CA Root để ký...")
    cert, serial = ca_sign_csr(
        csr, ca_cert, ca_key,
        ocsp_url=ocsp_url,
        crl_url=crl_url,
        validity_days=validity_days,
        expired=expired,
    )
    log(f"[RA] CA Root đã ký thành công → serial={serial}")
    log("[RA] Trả certificate về cho Server.")
    return cert, serial
