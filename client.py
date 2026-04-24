"""
client.py
---------
Phần 3 của đề bài: Phía Client - quy trình xác thực chứng chỉ 5 bước.

  Bước 1: Verify chữ ký số (self-signed -> dùng public key trong chính cert).
  Bước 2: Kiểm tra thời hạn hiệu lực (Not Before / Not After).
  Bước 3: Kiểm tra hostname (khớp với SAN).
  Bước 4: Kiểm tra CRL (tải từ CRL Distribution Points và đối chiếu).
  Bước 5: Gửi yêu cầu OCSP để kiểm tra trạng thái trực tuyến.
"""

import json
import socket
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


# ============================================================================
#  Lấy chứng chỉ từ Socket server
# ============================================================================

def fetch_certificate(host: str, port: int, timeout: float = 5.0) -> bytes:
    """Kết nối Socket server, gửi 'GET_CERT', nhận về PEM bytes."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"GET_CERT")

        length_bytes = s.recv(4)
        if len(length_bytes) < 4:
            raise IOError("Không nhận được header độ dài từ server")
        length = int.from_bytes(length_bytes, "big")

        data = bytearray()
        while len(data) < length:
            chunk = s.recv(min(4096, length - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)


# ============================================================================
#  5 bước xác thực
# ============================================================================

def verify_signature(cert):
    """Bước 1: Verify chữ ký của chứng chỉ tự ký."""
    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            # Hệ thống này chỉ dùng RSA, nhưng để phòng hờ:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm,
            )
        return True, "Chữ ký HỢP LỆ (verified bằng public key của chính cert)"
    except InvalidSignature:
        return False, "Chữ ký KHÔNG hợp lệ - cert đã bị sửa đổi"
    except Exception as e:
        return False, f"Lỗi khi verify signature: {e}"


def _get_not_valid_times(cert):
    """Lấy not_valid_before / not_valid_after dạng UTC, tương thích nhiều phiên bản cryptography."""
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
        return nb, na


def check_validity(cert):
    """Bước 2: Kiểm tra Not Before / Not After."""
    now = datetime.now(timezone.utc)
    nb, na = _get_not_valid_times(cert)

    if now < nb:
        return False, f"Chứng chỉ CHƯA CÓ HIỆU LỰC (Not Before: {nb})"
    if now > na:
        return False, f"Chứng chỉ ĐÃ HẾT HẠN (Not After: {na})"
    return True, f"Trong thời hạn [{nb}  →  {na}]"


def check_hostname(cert, hostname: str):
    """Bước 3: Hostname phải khớp SAN."""
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return False, "Không có Subject Alternative Name extension"

    san = san_ext.value
    dns_names = san.get_values_for_type(x509.DNSName)
    ip_addresses = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    all_names = dns_names + ip_addresses

    if hostname in dns_names or hostname in ip_addresses:
        return True, f"Hostname '{hostname}' KHỚP với SAN: {all_names}"
    return False, f"Hostname '{hostname}' KHÔNG khớp với SAN: {all_names}"


def check_crl(cert):
    """Bước 4: Tải CRL từ URL trong CRL Distribution Points và đối chiếu."""
    try:
        crl_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
    except x509.ExtensionNotFound:
        return True, "Không có CRL Distribution Points (bỏ qua bước này)"

    crl_urls = []
    for dp in crl_ext.value:
        if dp.full_name:
            for gn in dp.full_name:
                if isinstance(gn, x509.UniformResourceIdentifier):
                    crl_urls.append(gn.value)

    if not crl_urls:
        return True, "CRL Distribution Points rỗng (bỏ qua)"

    for url in crl_urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                crl_data = resp.read()
            crl = x509.load_pem_x509_crl(crl_data)
            revoked_entry = crl.get_revoked_certificate_by_serial_number(
                cert.serial_number
            )
            if revoked_entry is not None:
                try:
                    rev_date = revoked_entry.revocation_date_utc
                except AttributeError:
                    rev_date = revoked_entry.revocation_date
                return False, (
                    f"Chứng chỉ BỊ THU HỒI theo CRL {url} "
                    f"(thu hồi lúc {rev_date})"
                )
            return True, f"Không có trong CRL (đã check {url})"
        except Exception as e:
            return False, f"Không tải được CRL từ {url}: {e}"

    return True, "OK"


def check_ocsp(cert):
    """Bước 5: Gọi OCSP service bằng HTTP đơn giản."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return True, "Không có AIA/OCSP URL (bỏ qua)"

    ocsp_urls = [
        ad.access_location.value
        for ad in aia.value
        if ad.access_method == AuthorityInformationAccessOID.OCSP
        and isinstance(ad.access_location, x509.UniformResourceIdentifier)
    ]
    if not ocsp_urls:
        return True, "Không có OCSP URL trong AIA (bỏ qua)"

    for url in ocsp_urls:
        full_url = f"{url}?serial={cert.serial_number}"
        try:
            with urllib.request.urlopen(full_url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            status = data.get("status", "UNKNOWN")
            if status == "GOOD":
                return True, f"OCSP status = GOOD (từ {url})"
            elif status == "REVOKED":
                return False, f"OCSP status = REVOKED (từ {url})"
            else:
                return False, f"OCSP status = {status}"
        except Exception as e:
            return False, f"Lỗi khi query OCSP {url}: {e}"

    return True, "OK"


# ============================================================================
#  Orchestrator: chạy đủ 5 bước và trả kết quả
# ============================================================================

def verify_certificate_full(cert_bytes: bytes, hostname: str, log_callback=None):
    """
    Chạy đủ quy trình 5 bước.

    Trả về: (overall_pass: bool, results: list[(name, ok, msg)], cert)
    """
    cert = x509.load_pem_x509_certificate(cert_bytes)

    def log(msg):
        if log_callback:
            log_callback(msg)

    steps = [
        ("Bước 1 - Verify chữ ký số", lambda: verify_signature(cert)),
        ("Bước 2 - Thời hạn hiệu lực", lambda: check_validity(cert)),
        (f"Bước 3 - Hostname ({hostname})", lambda: check_hostname(cert, hostname)),
        ("Bước 4 - CRL check", lambda: check_crl(cert)),
        ("Bước 5 - OCSP check", lambda: check_ocsp(cert)),
    ]

    results = []
    for name, fn in steps:
        log(f"── {name} ──")
        ok, msg = fn()
        log(f"   {'✓ PASS' if ok else '✗ FAIL'}: {msg}")
        results.append((name, ok, msg))

    overall = all(ok for _, ok, _ in results)
    return overall, results, cert
