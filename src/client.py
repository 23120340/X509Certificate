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

import hashlib
import json
import socket
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
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


def fetch_certificate(host: str, port: int, timeout: float = 5.0):
    """
    Kết nối socket server, gửi 'GET_CERT', nhận về PEM bytes của server cert.

    Trả về tuple (cert_bytes, peer_address) trong đó `peer_address` là
    "<ip>:<port>" thực sự đã kết nối — hữu ích cho audit khi `host` là
    hostname (có thể bị DNS đầu độc che giấu địa chỉ thật).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        peer_ip, peer_port = s.getpeername()[:2]
        peer_address = f"{peer_ip}:{peer_port}"
        s.sendall(b"GET_CERT")
        return _recv_blob(s), peer_address


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


# ── Pin warning + lưu cert (advisory, không ảnh hưởng overall pass) ─────────

def _cert_fingerprint_sha256(cert) -> str:
    """SHA-256 fingerprint của DER-encoded cert, dạng hex lowercase."""
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def _safe_hostname(hostname: str) -> str:
    """Sanitize hostname để làm tên thư mục an toàn trên mọi OS."""
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in hostname)


def save_server_cert(cert_bytes: bytes, cert, hostname: str,
                     base_dir: str = "received_certs",
                     peer_address: str | None = None) -> Path:
    """
    Lưu PEM nhận được + metadata JSON vào received_certs/<hostname>/.
    Tên file: <timestamp>_<fingerprint8>.pem (+ .json đi kèm).

    `peer_address` (nếu có) ghi vào JSON dưới dạng "<ip>:<port>" để biết
    *địa chỉ thực sự* đã kết nối — tách bạch với `hostname` do user nhập
    (vốn có thể bị DNS đầu độc).

    Trả về path file PEM.
    """
    host_dir = Path(base_dir) / _safe_hostname(hostname)
    host_dir.mkdir(parents=True, exist_ok=True)

    fp = _cert_fingerprint_sha256(cert)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    stem = f"{ts}_{fp[:8]}"

    pem_path = host_dir / f"{stem}.pem"
    json_path = host_dir / f"{stem}.json"

    pem_path.write_bytes(cert_bytes)

    nb, na = _get_not_valid_times(cert)
    metadata = {
        "hostname": hostname,
        "peer_address": peer_address,
        "fingerprint_sha256": fp,
        "serial_number": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": nb.isoformat(),
        "not_valid_after": na.isoformat(),
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    json_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return pem_path


def check_pinned(cert, hostname: str,
                 base_dir: str = "received_certs"):
    """
    So fingerprint hiện tại với pin.json đã lưu cho hostname.

    - Lần đầu (chưa có pin.json): tạo mới với fingerprint hiện tại (TOFU).
    - Khớp: cập nhật last_seen, trả OK.
    - Khác: WARN — KHÔNG tự cập nhật pin; cert có thể rotate hợp lệ
      HOẶC đang bị MITM. User phải xóa pin.json thủ công để chấp nhận.

    Trả về (ok: bool, msg: str). ok=False chỉ khi fingerprint mismatch.
    """
    host_dir = Path(base_dir) / _safe_hostname(hostname)
    host_dir.mkdir(parents=True, exist_ok=True)
    pin_path = host_dir / "pin.json"

    current_fp = _cert_fingerprint_sha256(cert)
    now_iso = datetime.now(timezone.utc).isoformat()

    if not pin_path.exists():
        pin_data = {
            "fingerprint_sha256": current_fp,
            "first_seen": now_iso,
            "last_seen": now_iso,
        }
        pin_path.write_text(json.dumps(pin_data, indent=2), encoding="utf-8")
        return True, (
            f"Pin TẠO MỚI cho '{hostname}' (TOFU) — "
            f"fingerprint={current_fp[:16]}…"
        )

    pin_data = json.loads(pin_path.read_text(encoding="utf-8"))
    pinned_fp = pin_data.get("fingerprint_sha256", "")

    if pinned_fp == current_fp:
        pin_data["last_seen"] = now_iso
        pin_path.write_text(json.dumps(pin_data, indent=2), encoding="utf-8")
        return True, (
            f"Pin KHỚP — fingerprint={current_fp[:16]}… "
            f"(first seen {pin_data.get('first_seen', '?')})"
        )

    return False, (
        f"⚠ Pin MISMATCH cho '{hostname}'! "
        f"Đã pin={pinned_fp[:16]}…, nhận được={current_fp[:16]}…. "
        f"Cert có thể được rotate HỢP LỆ hoặc đang bị MITM. "
        f"Xóa {pin_path} nếu chấp nhận cert mới."
    )


# ── Orchestrator ──────────────────────────────────────────────────────────────

def verify_certificate_full(cert_bytes: bytes, hostname: str,
                            trust_store_dir: str,
                            log_callback=None,
                            pin_dir: str = "received_certs",
                            peer_address: str | None = None):
    """
    Chạy đủ 5 bước xác thực trong mô hình Root CA + Trust Store.

    `trust_store_dir` là đường dẫn thư mục chứa Root CA certs tin cậy.
    `pin_dir` là thư mục lưu cert nhận được + pin.json cho mỗi hostname.
    `peer_address` (tuỳ chọn) là "<ip>:<port>" thực sự đã kết nối — ghi
    vào JSON metadata để audit, tách bạch với hostname người dùng nhập.

    Trả về (overall_pass: bool, results: list[(name, ok, msg)], cert).
    Bước phụ "Pin warning + lưu cert" được thêm vào `results` nhưng
    KHÔNG tính vào `overall_pass`.
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

    # ── Bước phụ: lưu cert + pin warning (advisory, không tính vào overall) ──
    log("── Bước phụ - Lưu cert + Pin warning (advisory) ──")
    try:
        pem_path = save_server_cert(
            cert_bytes, cert, hostname,
            base_dir=pin_dir, peer_address=peer_address,
        )
        log(f"   ✓ Đã lưu cert tại: {pem_path} (peer={peer_address or 'n/a'})")
    except Exception as e:
        log(f"   ✗ Lỗi khi lưu cert: {e}")

    try:
        pin_ok, pin_msg = check_pinned(cert, hostname, base_dir=pin_dir)
        log(f"   {'✓' if pin_ok else '⚠'} {pin_msg}")
        results.append(("Bước phụ - Pin warning (advisory)", pin_ok, pin_msg))
    except Exception as e:
        log(f"   ✗ Lỗi khi check pin: {e}")
        results.append(("Bước phụ - Pin warning (advisory)", True,
                        f"Bỏ qua do lỗi: {e}"))

    return overall, results, cert
