"""
client.py
---------
Phía Client:
  - Nhận CA cert + Server cert từ socket server.
  - Xác thực server certificate theo 5 bước (chữ ký dùng CA Root public key).
  - Gửi tin nhắn mã hóa (RSA-OAEP) tới server và nhận phản hồi.
"""

import json
import socket
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# ============================================================================
#  Nhận certificate chain từ Socket server
# ============================================================================

def _recv_blob(s) -> bytes:
    """Đọc một blob length-prefixed (4 bytes big-endian + data)."""
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


def fetch_certificate(host: str, port: int, timeout: float = 5.0):
    """
    Kết nối server, gửi 'GET_CERT'.
    Trả về (ca_pem: bytes, server_pem: bytes).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"GET_CERT")
        ca_pem = _recv_blob(s)
        server_pem = _recv_blob(s)
    return ca_pem, server_pem


def send_encrypted_message(
    host: str,
    port: int,
    message: str,
    server_cert,
    timeout: float = 5.0,
) -> str:
    """
    Mã hóa message bằng public key của server (RSA-OAEP),
    gửi tới server, nhận và trả về phản hồi dạng string.
    """
    public_key = server_cert.public_key()
    encrypted = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    hex_payload = encrypted.hex()
    request = f"MSG_ENC:{hex_payload}"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(request.encode("utf-8"))
        response = _recv_blob(s)
    return response.decode("utf-8")


# ============================================================================
#  5 bước xác thực
# ============================================================================

def verify_signature(server_cert, ca_cert):
    """Bước 1: Verify chữ ký server cert bằng public key của CA Root."""
    ca_public_key = ca_cert.public_key()
    try:
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm,
            )
        else:
            ca_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                server_cert.signature_hash_algorithm,
            )
        return True, "Chữ ký HỢP LỆ (CA Root public key xác nhận)"
    except InvalidSignature:
        return False, "Chữ ký KHÔNG hợp lệ — cert bị giả mạo hoặc sai CA"
    except Exception as e:
        return False, f"Lỗi khi verify signature: {e}"


def _get_not_valid_times(cert):
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
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
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
    """Bước 4: Tải CRL từ CRL Distribution Points và đối chiếu serial."""
    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        return True, "Không có CRL Distribution Points (bỏ qua)"

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
            revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
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
    """Bước 5: Gọi OCSP service kiểm tra trạng thái trực tuyến."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
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
#  Orchestrator: chạy đủ 5 bước
# ============================================================================

def verify_certificate_full(ca_pem: bytes, server_pem: bytes, hostname: str, log_callback=None):
    """
    Xác thực server certificate theo 5 bước.
    Trả về (overall_pass: bool, results: list[(name, ok, msg)], server_cert, ca_cert).
    """
    ca_cert = x509.load_pem_x509_certificate(ca_pem)
    server_cert = x509.load_pem_x509_certificate(server_pem)

    def log(msg):
        if log_callback:
            log_callback(msg)

    steps = [
        ("Bước 1 - Verify chữ ký (CA Root)", lambda: verify_signature(server_cert, ca_cert)),
        ("Bước 2 - Thời hạn hiệu lực",       lambda: check_validity(server_cert)),
        (f"Bước 3 - Hostname ({hostname})",   lambda: check_hostname(server_cert, hostname)),
        ("Bước 4 - CRL check",                lambda: check_crl(server_cert)),
        ("Bước 5 - OCSP check",               lambda: check_ocsp(server_cert)),
    ]

    results = []
    for name, fn in steps:
        log(f"── {name} ──")
        ok, msg = fn()
        log(f"   {'✓ PASS' if ok else '✗ FAIL'}: {msg}")
        results.append((name, ok, msg))

    overall = all(ok for _, ok, _ in results)
    return overall, results, server_cert, ca_cert
