"""
core/crl.py
-----------
Quản lý Certificate Revocation List (CRL) và OCSP database.

Hai nguồn sự thật tách biệt:
  ocsp_db.json → OCSP server đọc, luôn realtime/fresh
  crl.pem      → chỉ update khi user bấm "Publish CRL Now"
"""

import json
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from core import keyalg


# ── Xây dựng và lưu CRL ──────────────────────────────────────────────────────

def build_crl(issuer_cert, issuer_key, revoked_serials, validity_days: int = 7,
              hash_algorithm=None, revocation_dates=None):
    """
    Tạo CRL ký bởi issuer_key. revoked_serials là list[int].

    `hash_algorithm` (HashAlgorithm hoặc None) cho phép cấu hình hàm băm chữ
    ký CRL; với khóa Ed25519 sẽ tự bỏ qua hash.

    `revocation_dates` (dict[int, datetime] | None): NGÀY THU HỒI THỰC của từng
    serial (lấy từ issued_certs.revoked_at). Serial nào không có trong dict →
    fallback dùng `now` (thời điểm build CRL). Nhờ vậy mỗi entry giữ đúng mốc
    thu hồi của nó, không bị đặt lại theo thời điểm publish.
    """
    now = datetime.now(timezone.utc)
    revocation_dates = revocation_dates or {}
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=validity_days))
    )
    for serial in revoked_serials:
        s = int(serial)
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(revocation_dates.get(s, now))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(
        private_key=issuer_key,
        algorithm=keyalg.signing_algorithm(issuer_key, hash_algorithm),
    )


def save_crl(crl, crl_path: str):
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))


def load_crl(crl_path: str):
    with open(crl_path, "rb") as f:
        return x509.load_pem_x509_crl(f.read())


# ── OCSP DB (realtime) ───────────────────────────────────────────────────────

def save_revoked_list(revoked_serials, path: str):
    """Ghi toàn bộ danh sách serial bị revoke ra JSON."""
    with open(path, "w") as f:
        json.dump([str(s) for s in revoked_serials], f)


def load_revoked_list(path: str) -> set:
    """Đọc danh sách serial bị revoke từ JSON. Trả về set[int]."""
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        data = json.load(f)
    return set(int(s) for s in data)


def revoke_serial_ocsp_only(serial: int, ocsp_db_path: str):
    """
    Thêm serial vào OCSP DB mà KHÔNG cập nhật CRL.
    Dùng cho flavor revoked_ocsp_only để demo khoảng cách CRL vs OCSP.
    """
    revoked = load_revoked_list(ocsp_db_path)
    revoked.add(serial)
    save_revoked_list(list(revoked), ocsp_db_path)


def build_and_publish_crl(issuer_cert, issuer_key, ocsp_db_path: str, crl_path: str):
    """
    Snapshot toàn bộ OCSP DB → build CRL → ghi ra crl_path.
    Tương đương bấm nút "Publish CRL Now" trên GUI.
    """
    revoked_serials = load_revoked_list(ocsp_db_path)
    crl = build_crl(issuer_cert, issuer_key, list(revoked_serials))
    save_crl(crl, crl_path)
    return crl


def unrevoke_serial(serial: int, ocsp_db_path: str):
    """
    Xóa serial khỏi OCSP DB (rollback khi xóa server khỏi demo).
    CRL không thay đổi tự động — cần Publish CRL Now để đồng bộ.
    """
    revoked = load_revoked_list(ocsp_db_path)
    revoked.discard(serial)
    save_revoked_list(list(revoked), ocsp_db_path)
