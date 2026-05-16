"""
core/encryption.py
------------------
Encryption-at-rest cho dữ liệu nhạy cảm (đáp ứng "lưu ý C" của đồ án).

Hai cơ chế độc lập:

  1) Password hashing — KHÔNG có ý định đảo ngược.
        hash_password / verify_password
     Dùng scrypt (stdlib `hashlib.scrypt`) với salt 16 bytes ngẫu nhiên.
     Format chuỗi tự-mô-tả: "scrypt$N$r$p$salt_hex$hash_hex" để có thể
     tăng tham số sau này mà vẫn verify được hash cũ.

  2) Symmetric encryption cho private keys — CÓ ý định đảo ngược.
        encrypt_blob / decrypt_blob
     AES-256-GCM, 12-byte nonce ngẫu nhiên mỗi lần encrypt, auth tag
     đính cuối ciphertext (do AESGCM API quản lý).

Master key:
  • File `master.key` (32 bytes random) ở project root.
  • Tự sinh ở lần init đầu tiên, sau đó đọc lại.
  • CẢNH BÁO: trong production thực tế, master key phải để trong HSM/KMS
    chứ không phải file phẳng. Demo dùng file để chạy được offline.
"""

import hashlib
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Master key ────────────────────────────────────────────────────────────────

DEFAULT_MASTER_KEY_PATH = "master.key"
MASTER_KEY_SIZE = 32   # AES-256
GCM_NONCE_SIZE  = 12   # khuyến nghị NIST cho AES-GCM

_master_key_cache: "bytes | None" = None


def _load_or_create_master_key(path: str) -> bytes:
    p = Path(path)
    if p.exists():
        data = p.read_bytes()
        if len(data) != MASTER_KEY_SIZE:
            raise ValueError(
                f"Master key tại {path!r} sai kích thước "
                f"({len(data)} bytes, cần {MASTER_KEY_SIZE})."
            )
        return data
    key = secrets.token_bytes(MASTER_KEY_SIZE)
    if p.parent and str(p.parent) not in ("", "."):
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key)
    try:
        os.chmod(p, 0o600)  # POSIX; Windows ignores
    except OSError:
        pass
    return key


def get_master_key(path: str = DEFAULT_MASTER_KEY_PATH) -> bytes:
    """Lazy-load + cache master key. Lần đầu sẽ sinh và ghi file."""
    global _master_key_cache
    if _master_key_cache is None:
        _master_key_cache = _load_or_create_master_key(path)
    return _master_key_cache


def reset_master_key_cache() -> None:
    """Xóa cache (dùng cho test, khi đổi DEFAULT_MASTER_KEY_PATH giữa các test)."""
    global _master_key_cache
    _master_key_cache = None


# ── Symmetric encryption (AES-256-GCM) ───────────────────────────────────────

def encrypt_blob(plaintext: bytes, aad: "bytes | None" = None,
                 master_key_path: str = DEFAULT_MASTER_KEY_PATH
                 ) -> "tuple[bytes, bytes]":
    """
    AES-GCM encrypt. Trả về (nonce, ciphertext_with_auth_tag).
    `aad` (associated data) không được mã hóa nhưng được xác thực — dùng để
    bind ciphertext với context (vd: f"users:{user_id}").
    """
    nonce = secrets.token_bytes(GCM_NONCE_SIZE)
    aesgcm = AESGCM(get_master_key(master_key_path))
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt_blob(nonce: bytes, ciphertext: bytes, aad: "bytes | None" = None,
                 master_key_path: str = DEFAULT_MASTER_KEY_PATH) -> bytes:
    """AES-GCM decrypt. Raise InvalidTag nếu sai key/nonce/aad hay ciphertext bị sửa."""
    aesgcm = AESGCM(get_master_key(master_key_path))
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ── Password hashing (scrypt) ────────────────────────────────────────────────

# Tham số scrypt: ~64 MB memory, ~0.1s trên CPU hiện đại. Đủ chậm cho brute-
# force offline, đủ nhanh cho UX login.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_SALT_LEN = 16


def hash_password(password: str) -> str:
    """
    Hash password. Trả về chuỗi self-describing:
        "scrypt$N$r$p$salt_hex$hash_hex"
    Tham số nhúng trong chuỗi để verify được hash cũ kể cả khi đổi tham số sau.
    """
    if not isinstance(password, str):
        raise TypeError("password phải là str")
    salt = secrets.token_bytes(_SCRYPT_SALT_LEN)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time compare. Trả về False thay vì raise nếu format lỗi."""
    if not isinstance(password, str) or not isinstance(hashed, str):
        return False
    try:
        scheme, n_str, r_str, p_str, salt_hex, hash_hex = hashed.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    try:
        n, r, p = int(n_str), int(r_str), int(p_str)
        salt     = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    try:
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt, n=n, r=r, p=p, dklen=len(expected),
        )
    except (ValueError, MemoryError):
        return False
    return secrets.compare_digest(derived, expected)
