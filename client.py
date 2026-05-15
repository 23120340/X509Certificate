"""
client.py
---------
Phía Client — 5 bước xác thực chứng chỉ X.509 trong mô hình
Root CA + Trust Store.

  Bước 1: Verify chữ ký server cert bằng Root CA public key trong Trust Store.
          (server cert được Root CA ký, KHÔNG còn self-signed)
  Bước 2: Kiểm tra thời hạn hiệu lực (Not Before / Not After).
  Bước 3: Kiểm tra hostname (khớp với SAN).
  Bước 4: Kiểm tra CRL — verify chữ ký CRL bằng Root CA rồi đối chiếu serial.
  Bước 5: Gửi yêu cầu OCSP kiểm tra trạng thái trực tuyến.
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

from issuer import load_trust_store


# ── Giao tiếp với Socket server ──────────────────────────────────────────────

def _recv_blob(s) -> bytes:
    """Đọc một blob có tiền tố 4 byte độ dài (big-endian)."""
    header = s.recv(4)
    if len(header) < 4:
        raise IOError("Không nhận được header độ dài từ server")
    length = int.from_bytes(header, "big")
    data = bytearray()
    while len(data) < length:
        chunk = s.recv(min(4096, length - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def fetch_certificate(host: str, port: int, timeout: float = 5.0) -> bytes:
    """Kết nối socket server, gửi 'GET_CERT', nhận về PEM bytes của server cert."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"GET_CERT")
        return _recv_blob(s)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _verify_signature_with_pubkey(public_key, signature, tbs_bytes, hash_algorithm):
    """
    Gọi public_key.verify(...) đúng tham số tùy loại khóa.
    Raise InvalidSignature nếu chữ ký sai.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature,
            tbs_bytes,
            padding.PKCS1v15(),
            hash_algorithm,
        )
    else:
        public_key.verify(signature, tbs_bytes, hash_algorithm)


def _find_trusted_issuer(cert, trusted_cas):
    """
    Tìm Root CA trong trust store có subject khớp với issuer của cert.
    Trả về cert Root CA hoặc None.
    """
    for ca in trusted_cas:
        if ca.subject == cert.issuer:
            return ca
    return None


# ── 5 bước xác thực ──────────────────────────────────────────────────────────

def verify_signature(cert, trusted_cas):
    """
    Bước 1: Verify chữ ký server cert bằng Root CA public key trong Trust Store.

    Logic:
      1. Lấy issuer name từ server cert.
      2. Tìm Root CA trong trust store có subject khớp issuer.
      3. Dùng public key của Root CA verify chữ ký server cert.
    Nếu Trust Store rỗng hoặc không tìm thấy issuer phù hợp → FAIL.
    """
    if not trusted_cas:
        return False, "Trust Store rỗng — không có Root CA để verify"

    issuer_ca = _find_trusted_issuer(cert, trusted_cas)
    if issuer_ca is None:
        return False, (
            f"Không tìm thấy Root CA tin cậy có subject khớp issuer="
            f"'{cert.issuer.rfc4514_string()}' trong Trust Store"
        )

    try:
        _verify_signature_with_pubkey(
            issuer_ca.public_key(),
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm,
        )
        return True, (
            f"Chữ ký HỢP LỆ — verified bằng Root CA "
            f"'{issuer_ca.subject.rfc4514_string()}' trong Trust Store"
        )
    except InvalidSignature:
        return False, "Chữ ký KHÔNG hợp lệ — cert bị giả mạo hoặc tampered"
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
    """Bước 3: Hostname phải khớp với SAN."""
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return False, "Không có Subject Alternative Name extension"

    san = san_ext.value
    dns_names   = san.get_values_for_type(x509.DNSName)
    ip_addresses = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    all_names   = dns_names + ip_addresses

    if hostname in dns_names or hostname in ip_addresses:
        return True, f"Hostname '{hostname}' KHỚP với SAN: {all_names}"
    return False, f"Hostname '{hostname}' KHÔNG khớp với SAN: {all_names}"


def _verify_crl_signature(crl, trusted_cas):
    """
    Tìm Root CA tin cậy phát hành CRL và verify chữ ký CRL.
    Trả về (ok: bool, issuer_ca, error_msg).
    """
    issuer_ca = None
    for ca in trusted_cas:
        if ca.subject == crl.issuer:
            issuer_ca = ca
            break
    if issuer_ca is None:
        return False, None, (
            f"CRL issuer '{crl.issuer.rfc4514_string()}' không khớp Root CA nào "
            f"trong Trust Store"
        )

    # cryptography ≥ 40 có CRL.is_signature_valid(public_key); fallback raw verify.
    try:
        if hasattr(crl, "is_signature_valid"):
            ok = crl.is_signature_valid(issuer_ca.public_key())
            if not ok:
                return False, issuer_ca, "Chữ ký CRL KHÔNG hợp lệ"
            return True, issuer_ca, ""
        _verify_signature_with_pubkey(
            issuer_ca.public_key(),
            crl.signature,
            crl.tbs_certlist_bytes,
            crl.signature_hash_algorithm,
        )
        return True, issuer_ca, ""
    except InvalidSignature:
        return False, issuer_ca, "Chữ ký CRL KHÔNG hợp lệ"
    except Exception as e:
        return False, issuer_ca, f"Lỗi khi verify chữ ký CRL: {e}"


def check_crl(cert, trusted_cas):
    """
    Bước 4: Tải CRL từ CRL Distribution Points, verify chữ ký CRL bằng
    Root CA trong Trust Store, sau đó đối chiếu serial.
    """
    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        return True, "Không có CRL Distribution Points (bỏ qua)"

    crl_urls = [
        gn.value
        for dp in crl_ext.value
        if dp.full_name
        for gn in dp.full_name
        if isinstance(gn, x509.UniformResourceIdentifier)
    ]
    if not crl_urls:
        return True, "CRL Distribution Points rỗng (bỏ qua)"

    for url in crl_urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                crl_data = resp.read()
            crl = x509.load_pem_x509_crl(crl_data)

            sig_ok, issuer_ca, err = _verify_crl_signature(crl, trusted_cas)
            if not sig_ok:
                return False, f"CRL không đáng tin từ {url}: {err}"

            entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            if entry is not None:
                try:
                    rev_date = entry.revocation_date_utc
                except AttributeError:
                    rev_date = entry.revocation_date
                return False, (
                    f"Chứng chỉ BỊ THU HỒI theo CRL (thu hồi lúc {rev_date}; "
                    f"CRL ký bởi '{issuer_ca.subject.rfc4514_string()}')"
                )
            return True, (
                f"Không có trong CRL ({url}); CRL signature OK theo Root CA"
            )
        except Exception as e:
            return False, f"Không tải/verify được CRL từ {url}: {e}"

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
        try:
            with urllib.request.urlopen(f"{url}?serial={cert.serial_number}", timeout=5) as resp:
                data = json.loads(resp.read().decode())
            status = data.get("status", "UNKNOWN")
            if status == "GOOD":
                return True, f"OCSP status = GOOD (từ {url})"
            elif status == "REVOKED":
                return False, f"OCSP status = REVOKED (từ {url})"
            else:
                return False, f"OCSP status không xác định: {status}"
        except Exception as e:
            return False, f"Lỗi khi query OCSP {url}: {e}"

    return True, "OK"


# ── Orchestrator ──────────────────────────────────────────────────────────────

def verify_certificate_full(cert_bytes: bytes, hostname: str,
                            trust_store_dir: str,
                            log_callback=None):
    """
    Chạy đủ 5 bước xác thực trong mô hình Root CA + Trust Store.

    `trust_store_dir` là đường dẫn thư mục chứa Root CA certs tin cậy.
    Trả về (overall_pass: bool, results: list[(name, ok, msg)], cert).
    """
    cert = x509.load_pem_x509_certificate(cert_bytes)
    trusted_cas = load_trust_store(trust_store_dir)

    def log(msg):
        if log_callback:
            log_callback(msg)

    if trusted_cas:
        ca_names = ", ".join(ca.subject.rfc4514_string() for ca in trusted_cas)
        log(f"Trust Store ({trust_store_dir}) chứa: {ca_names}")
    else:
        log(f"⚠ Trust Store ({trust_store_dir}) RỖNG — Bước 1/4 sẽ FAIL")

    steps = [
        ("Bước 1 - Verify chữ ký bằng Root CA (Trust Store)",
            lambda: verify_signature(cert, trusted_cas)),
        ("Bước 2 - Thời hạn hiệu lực",
            lambda: check_validity(cert)),
        (f"Bước 3 - Hostname ({hostname})",
            lambda: check_hostname(cert, hostname)),
        ("Bước 4 - CRL check (verify chữ ký CRL bằng Root CA)",
            lambda: check_crl(cert, trusted_cas)),
        ("Bước 5 - OCSP check",
            lambda: check_ocsp(cert)),
    ]

    results = []
    for name, fn in steps:
        log(f"── {name} ──")
        ok, msg = fn()
        log(f"   {'✓ PASS' if ok else '✗ FAIL'}: {msg}")
        results.append((name, ok, msg))

    overall = all(ok for _, ok, _ in results)
    return overall, results, cert
