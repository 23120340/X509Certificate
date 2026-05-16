"""
services/customer_keys.py
-------------------------
Customer keypair (B.4) — sinh + lưu encrypted RSA keypair cho khách hàng.

Mỗi keypair có:
  • owner_id     — chủ sở hữu (user.id, role=customer)
  • name         — nickname để user phân biệt (unique trong owner)
  • public_key_pem    — PEM của public key (lưu plain, ai cũng đọc được)
  • encrypted_private_key — PKCS#8 PEM đã mã hóa AES-GCM
  • gcm_nonce    — 12 bytes
  • aad          = b"customer_keys:{id}"

Mọi truy cập đều yêu cầu `owner_id`: lớp service KHÔNG tin caller có đúng quyền,
luôn WHERE owner_id=? để chống tham chiếu chéo (BOLA / IDOR).
"""

from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.encryption import encrypt_blob, decrypt_blob
from db.connection import conn_scope, transaction


ALLOWED_KEY_SIZES = (2048, 3072, 4096)


class CustomerKeyError(Exception):
    """Lỗi nghiệp vụ khi thao tác keypair khách hàng."""


def _aad_for(key_id: int) -> bytes:
    return f"customer_keys:{key_id}".encode("ascii")


def _serialize_private_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _serialize_public_pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ── Public API ───────────────────────────────────────────────────────────────

def generate_keypair(
    owner_id: int,
    name: str,
    key_size: int,
    db_path: str,
) -> dict:
    """
    Sinh RSA keypair + lưu vào DB.

    Vì AAD phụ thuộc id (chưa biết trước INSERT), ta:
      1. INSERT row tạm với placeholder để có id
      2. Encrypt với AAD đúng
      3. UPDATE row đó với ciphertext + nonce thật
    Tất cả trong 1 transaction → atomic.
    """
    name = (name or "").strip()
    if not name:
        raise CustomerKeyError("Tên keypair không được rỗng.")
    if len(name) > 64:
        raise CustomerKeyError("Tên keypair dài quá 64 ký tự.")
    if key_size not in ALLOWED_KEY_SIZES:
        raise CustomerKeyError(
            f"Key size không hợp lệ: {key_size}. "
            f"Chọn 1 trong {ALLOWED_KEY_SIZES}."
        )

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = _serialize_private_pem(rsa_key)
    pub_pem  = _serialize_public_pem(rsa_key)
    now = datetime.now(timezone.utc).isoformat()

    with transaction(db_path) as conn:
        # Check duplicate name within owner
        dup = conn.execute(
            "SELECT 1 FROM customer_keys WHERE owner_id = ? AND name = ?",
            (owner_id, name),
        ).fetchone()
        if dup:
            raise CustomerKeyError(
                f"Bạn đã có keypair tên '{name}'. Dùng tên khác."
            )

        # Insert placeholder để có id, AAD sẽ bind với id thật
        cur = conn.execute(
            "INSERT INTO customer_keys "
            "(owner_id, name, algorithm, key_size, public_key_pem, "
            " encrypted_private_key, gcm_nonce, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (owner_id, name, "RSA", key_size, pub_pem,
             b"", b"", now),
        )
        key_id = cur.lastrowid

        nonce, ct = encrypt_blob(priv_pem, aad=_aad_for(key_id))
        conn.execute(
            "UPDATE customer_keys SET encrypted_private_key = ?, gcm_nonce = ? "
            "WHERE id = ?",
            (ct, nonce, key_id),
        )

    return {
        "id":         key_id,
        "owner_id":   owner_id,
        "name":       name,
        "algorithm":  "RSA",
        "key_size":   key_size,
        "created_at": now,
    }


def list_keys(owner_id: int, db_path: str) -> "list[dict]":
    """Danh sách keypair của user (metadata, không có private key)."""
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT id, name, algorithm, key_size, public_key_pem, created_at "
            "FROM customer_keys WHERE owner_id = ? ORDER BY id DESC",
            (owner_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_key_meta(key_id: int, owner_id: int, db_path: str) -> Optional[dict]:
    """Metadata + public_key_pem của 1 keypair. Trả về None nếu không thấy
    HOẶC không thuộc owner."""
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT id, owner_id, name, algorithm, key_size, public_key_pem, "
            "       created_at FROM customer_keys "
            "WHERE id = ? AND owner_id = ?",
            (key_id, owner_id),
        ).fetchone()
        return dict(row) if row else None


def load_private_key(key_id: int, owner_id: int, db_path: str):
    """
    Decrypt + parse private key. Raise CustomerKeyError nếu:
      • không tìm thấy key id
      • key không thuộc owner_id (BOLA guard)
    """
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT encrypted_private_key, gcm_nonce FROM customer_keys "
            "WHERE id = ? AND owner_id = ?",
            (key_id, owner_id),
        ).fetchone()
    if row is None:
        raise CustomerKeyError(
            f"Không tìm thấy keypair id={key_id} thuộc về bạn."
        )
    pem = decrypt_blob(
        row["gcm_nonce"], row["encrypted_private_key"], aad=_aad_for(key_id),
    )
    return serialization.load_pem_private_key(pem, password=None)


def delete_key(key_id: int, owner_id: int, db_path: str) -> None:
    """
    Xóa keypair. Refuse nếu key đang được tham chiếu bởi 1 CSR/cert nào.
    """
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM customer_keys WHERE id = ? AND owner_id = ?",
            (key_id, owner_id),
        ).fetchone()
        if row is None:
            raise CustomerKeyError("Không tìm thấy keypair này.")

        in_use = conn.execute(
            "SELECT COUNT(*) AS n FROM csr_requests WHERE customer_key_id = ?",
            (key_id,),
        ).fetchone()["n"]
        if in_use > 0:
            raise CustomerKeyError(
                f"Keypair đang được dùng bởi {in_use} CSR — không thể xóa."
            )

        conn.execute(
            "DELETE FROM customer_keys WHERE id = ? AND owner_id = ?",
            (key_id, owner_id),
        )
