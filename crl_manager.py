"""
crl_manager.py
--------------
Phần 4 của đề bài: Quản lý Certificate Revocation List (CRL).

- Tạo một file CRL chuẩn X.509 chứa danh sách các serial bị thu hồi.
- Ngoài ra lưu thêm 1 file JSON revoked_serials.json cho OCSP server đọc
  (để OCSP tra trạng thái GOOD/REVOKED mà không phải parse CRL mỗi lần).
"""

import json
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def build_crl(issuer_cert, issuer_key, revoked_serials, validity_days: int = 7):
    """Tạo CRL ký bởi issuer_key. revoked_serials là list số (int)."""
    now = datetime.now(timezone.utc)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=validity_days))

    for serial in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial))
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def save_crl(crl, crl_path: str):
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))


def load_crl(crl_path: str):
    with open(crl_path, "rb") as f:
        return x509.load_pem_x509_crl(f.read())


# ---- Danh sách revoked dạng JSON dùng cho OCSP ----

def save_revoked_list(revoked_serials, path: str):
    with open(path, "w") as f:
        json.dump([str(s) for s in revoked_serials], f)


def load_revoked_list(path: str):
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        data = json.load(f)
    return set(int(s) for s in data)
