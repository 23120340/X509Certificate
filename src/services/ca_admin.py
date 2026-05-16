"""
services/ca_admin.py
--------------------
Root CA management — đáp ứng A.4 (sinh keypair Root CA) + A.5 (phát sinh
Root Certificate cho toàn hệ thống).

Khác legacy `core/ca.py.load_or_create_issuer` (lưu cert/key ra file):
ở đây private key được **encrypt-at-rest** bằng AES-256-GCM trước khi lưu
vào DB (đáp ứng lưu ý C của đồ án).

  create_root_ca(...)             — sinh keypair + Root cert + lưu encrypted vào DB.
                                    Tự deactivate Root CA cũ (nếu có).
  get_active_root_ca(...)         — đọc metadata Root CA active (KHÔNG decrypt key).
  list_root_ca_history(...)       — toàn bộ Root CA đã từng có (active + retired).
  load_active_root_ca_with_key()  — decrypt key, return (cert_obj, key_obj).
                                    DÙNG KHI: ký cert mới, ký CRL.
  publish_active_to_trust_store() — ghi Root CA cert ra file PEM trong
                                    trust_store_dir (client/CRL server đọc).
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core.encryption import encrypt_blob, decrypt_blob
from db.connection import conn_scope, transaction


ALLOWED_KEY_SIZES = (2048, 3072, 4096)
ROOT_CA_AAD = b"root_ca"


class CAError(Exception):
    """Lỗi nghiệp vụ trong CA admin service."""


# ── Crypto: sinh Root CA (cert + key) ────────────────────────────────────────

def _generate_root_ca(common_name: str, key_size: int, validity_days: int):
    """
    Sinh Root CA self-signed mới. Không lưu disk hay DB — caller xử lý.

    BasicConstraints(ca=True, path_length=0) → Root CA chỉ ký end-entity cert,
    không ký intermediate. Giữ nhất quán với issuer.py legacy.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME,       common_name),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _serialize_private_key_pem(key) -> bytes:
    """PKCS8 PEM, không password (mã hóa nằm ở tầng AES-GCM)."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert_validity_iso(cert) -> "tuple[str, str]":
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return nb.isoformat(), na.isoformat()


# ── Public API ───────────────────────────────────────────────────────────────

def create_root_ca(
    common_name: str,
    key_size: int,
    validity_days: int,
    created_by: int,
    db_path: str,
) -> dict:
    """
    Sinh Root CA mới + lưu encrypted vào bảng `root_ca`. Atomic:
      • Set is_active=0 cho mọi row cũ.
      • INSERT row mới với is_active=1.
    Trả về dict metadata (không có private key).
    Raise CAError nếu input không hợp lệ.
    """
    if not common_name or not common_name.strip():
        raise CAError("common_name không được rỗng.")
    common_name = common_name.strip()
    if key_size not in ALLOWED_KEY_SIZES:
        raise CAError(
            f"key_size không hợp lệ: {key_size}. "
            f"Chọn 1 trong {ALLOWED_KEY_SIZES}."
        )
    if validity_days < 1:
        raise CAError("validity_days phải >= 1.")

    cert, key = _generate_root_ca(common_name, key_size, validity_days)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem  = _serialize_private_key_pem(key)

    # Encrypt-at-rest. AAD = b"root_ca" để bind ciphertext với loại record
    # (decrypt ở context khác sẽ fail tag check).
    nonce, ct = encrypt_blob(key_pem, aad=ROOT_CA_AAD)

    not_before, not_after = _cert_validity_iso(cert)
    serial_hex = f"{cert.serial_number:x}"
    created_at = datetime.now(timezone.utc).isoformat()

    with transaction(db_path) as conn:
        conn.execute("UPDATE root_ca SET is_active = 0 WHERE is_active = 1")
        cur = conn.execute(
            "INSERT INTO root_ca "
            "(common_name, serial_hex, cert_pem, encrypted_private_key, "
            " gcm_nonce, not_valid_before, not_valid_after, created_at, "
            " created_by, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (common_name, serial_hex, cert_pem, ct, nonce,
             not_before, not_after, created_at, created_by),
        )
        new_id = cur.lastrowid

    return {
        "id":               new_id,
        "common_name":      common_name,
        "serial_hex":       serial_hex,
        "not_valid_before": not_before,
        "not_valid_after":  not_after,
        "created_at":       created_at,
        "created_by":       created_by,
        "is_active":        1,
        "key_size":         key_size,
        "validity_days":    validity_days,
    }


def get_active_root_ca(db_path: str) -> Optional[dict]:
    """
    Metadata + cert_pem của Root CA active. KHÔNG decrypt private key.
    Trả về None nếu chưa có Root CA.
    """
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT id, common_name, serial_hex, cert_pem, "
            "       not_valid_before, not_valid_after, created_at, "
            "       created_by, is_active "
            "FROM root_ca WHERE is_active = 1 LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


def list_root_ca_history(db_path: str) -> "list[dict]":
    """Tất cả Root CA đã từng có (newest first). Không gồm cert_pem (để gọn)."""
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT id, common_name, serial_hex, not_valid_before, "
            "       not_valid_after, created_at, created_by, is_active "
            "FROM root_ca ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def load_active_root_ca_with_key(db_path: str):
    """
    Decrypt private key + parse cert. Trả về (cert_obj, private_key_obj).
    Raise CAError nếu chưa có Root CA active.
    """
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT cert_pem, encrypted_private_key, gcm_nonce "
            "FROM root_ca WHERE is_active = 1 LIMIT 1"
        ).fetchone()
    if row is None:
        raise CAError("Chưa có Root CA active. Admin cần tạo Root CA trước.")

    cert = x509.load_pem_x509_certificate(row["cert_pem"])
    key_pem = decrypt_blob(
        row["gcm_nonce"], row["encrypted_private_key"], aad=ROOT_CA_AAD,
    )
    key = serialization.load_pem_private_key(key_pem, password=None)
    return cert, key


def publish_active_to_trust_store(db_path: str, trust_store_dir: str
                                   ) -> Optional[str]:
    """
    Ghi cert của Root CA active ra file PEM trong `trust_store_dir`.
    Trả về đường dẫn file đã ghi, hoặc None nếu chưa có Root CA active.

    Đây là cầu nối với các client/CRL server cũ vẫn load Root CA từ file.
    """
    ca = get_active_root_ca(db_path)
    if ca is None:
        return None
    os.makedirs(trust_store_dir, exist_ok=True)
    out_path = os.path.join(trust_store_dir, "root_ca.crt")
    with open(out_path, "wb") as f:
        f.write(ca["cert_pem"])
    return out_path
