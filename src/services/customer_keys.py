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

from core import keyalg
from core.encryption import encrypt_blob, decrypt_blob
from db.connection import conn_scope, transaction


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
    key_spec,
    db_path: str,
) -> dict:
    """
    Sinh keypair (RSA / ECDSA / Ed25519) + lưu vào DB.

    `key_spec` chấp nhận:
      • int (vd 2048)  → RSA với số bit đó (TƯƠNG THÍCH NGƯỢC với code/test cũ).
      • spec string    → 'RSA-2048' | 'RSA-3072' | 'RSA-4096' | 'EC-P256'
                          | 'EC-P384' | 'Ed25519'.

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

    try:
        key = keyalg.generate_key(key_spec)
    except keyalg.KeyAlgError as e:
        raise CustomerKeyError(str(e)) from e

    algorithm = keyalg.algorithm_label(key)   # 'RSA' / 'EC' / 'Ed25519'
    key_size  = keyalg.key_size_for(key)      # RSA bit / EC curve bit / 0
    priv_pem = _serialize_private_pem(key)
    pub_pem  = _serialize_public_pem(key)
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
            (owner_id, name, algorithm, key_size, pub_pem,
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
        "algorithm":  algorithm,
        "key_size":   key_size,
        "created_at": now,
    }


def list_keys(owner_id: int, db_path: str) -> "list[dict]":
    """Danh sách keypair của user (metadata, không có private key)."""
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT id, name, algorithm, key_size, public_key_pem, created_at, "
            "       compromised_at, "
            "       CASE WHEN length(encrypted_private_key) = 0 THEN 1 ELSE 0 END "
            "       AS is_public_only "
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
            "       created_at, compromised_at, "
            "       CASE WHEN length(encrypted_private_key) = 0 THEN 1 ELSE 0 END "
            "       AS is_public_only FROM customer_keys "
            "WHERE id = ? AND owner_id = ?",
            (key_id, owner_id),
        ).fetchone()
        return dict(row) if row else None


def _fingerprint_from_public_pem(pem) -> "str | None":
    """Fingerprint khóa từ public-key PEM (str/bytes). None nếu PEM hỏng —
    có WARN ra stderr để không âm thầm bỏ sót key khi đối chiếu lộ khóa
    (KHÔNG tự ý wipe key không đọc được: tránh phá nhầm key hợp lệ)."""
    try:
        raw = pem.encode("ascii") if isinstance(pem, str) else bytes(pem)
        pub = serialization.load_pem_public_key(raw)
    except Exception as e:
        import sys
        print(
            f"[customer_keys] WARN: public_key_pem không parse được khi đối "
            f"chiếu fingerprint (key có thể cần kiểm tra thủ công): {e}",
            file=sys.stderr,
        )
        return None
    return keyalg.public_key_fingerprint(pub)


def compromise_keys_for_fingerprint(
    fingerprint: str, db_path: str, owner_id: Optional[int] = None,
) -> "list[int]":
    """
    Đánh dấu MỌI keypair có public key khớp `fingerprint` là ĐÃ LỘ:
      • set compromised_at = now
      • WIPE encrypted_private_key + gcm_nonce → hủy bí mật, GIỮ metadata +
        public key (row trở thành 'public-only', không ký được nữa).

    KHÔNG xóa row: giữ lại để audit + chặn tái sử dụng (submit_csr từ chối key
    đã compromised). Idempotent: bỏ qua key đã đánh dấu trước đó.

    owner_id != None → chỉ trong phạm vi owner đó (cascade do customer yêu cầu,
    giữ kỷ luật BOLA). owner_id None → mọi owner (công cụ revoke-by-key của Admin).

    Trả về list id các key vừa được đánh dấu (chưa từng compromised).
    """
    now = datetime.now(timezone.utc).isoformat()
    affected: "list[int]" = []
    with transaction(db_path) as conn:
        rows = conn.execute(
            "SELECT id, owner_id, public_key_pem, compromised_at FROM customer_keys"
        ).fetchall()
        for r in rows:
            if owner_id is not None and r["owner_id"] != owner_id:
                continue
            if r["compromised_at"]:
                continue  # đã đánh dấu rồi
            if _fingerprint_from_public_pem(r["public_key_pem"]) != fingerprint:
                continue
            # Guard `compromised_at IS NULL` + rowcount: chỉ tính key thực sự
            # vừa được đánh dấu (chính xác kể cả khi có thao tác song song).
            cur = conn.execute(
                "UPDATE customer_keys SET compromised_at = ?, "
                "    encrypted_private_key = ?, gcm_nonce = ? "
                "WHERE id = ? AND compromised_at IS NULL",
                (now, b"", b"", r["id"]),
            )
            if cur.rowcount > 0:
                affected.append(r["id"])
    return affected


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
    if not row["encrypted_private_key"] or not row["gcm_nonce"]:
        raise CustomerKeyError(
            "Keypair này chỉ có public key từ CSR LAN; private key nằm trên máy client gốc."
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
