"""
core/keyalg.py
--------------
Nguồn sự thật DUY NHẤT cho thuật toán khóa công khai + hàm băm chữ ký.

Trước đây toàn hệ thống hardcode RSA + SHA-256 rải rác ở nhiều file. Module
này gom lại để hỗ trợ thêm các "công thức mã hóa" khác:

  • RSA      — 2048 / 3072 / 4096 bit
  • ECDSA    — đường cong P-256 (secp256r1) / P-384 (secp384r1)
  • Ed25519  — EdDSA (hàm băm cố định bên trong, không chọn hash ngoài)

API:
  generate_key(spec)                       → private key theo spec.
  signing_algorithm(private_key, hash)     → tham số `algorithm` đúng cho
        x509 builder .sign(): HashAlgorithm cho RSA/EC, None cho Ed25519/Ed448.
  verify_with_public_key(pub, sig, data, hash) → verify chữ ký đúng theo loại
        khóa (RSA PKCS1v15+hash / ECDSA(hash) / Ed thuần — không hash).
  hash_from_name(name)                     → 'SHA256'/'SHA384'/'SHA512' → obj.
  algorithm_label(key)                     → 'RSA'/'EC'/'Ed25519' (lưu DB + UI).
  key_size_for(key)                        → int cho cột key_size (RSA bit /
        EC curve bit / 0 cho Ed25519).
  describe(key)                            → nhãn người đọc, vd 'RSA 2048-bit'.

LƯU Ý Ed25519: cryptography yêu cầu .sign(key, algorithm=None) khi khóa là
Ed25519/Ed448 (không truyền hash). signing_algorithm() xử lý đúng việc này.
"""

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, ec, ed25519, ed448, padding,
)


RSA_KEY_SIZES = (2048, 3072, 4096)

# Spec string dùng cho UI (combobox) + làm tham số generate_key().
ALGO_CHOICES = (
    "RSA-2048", "RSA-3072", "RSA-4096",
    "EC-P256", "EC-P384",
    "Ed25519",
)

_HASHES = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512,
}

_EC_CURVES = {
    "EC-P256": ec.SECP256R1,
    "EC-P384": ec.SECP384R1,
    "P256": ec.SECP256R1,
    "P384": ec.SECP384R1,
}

# Hàm băm TỐI THIỂU theo đường cong ECDSA — ràng buộc backend (defense-in-depth)
# đồng bộ với UI: hash phải có độ mạnh >= đường cong (NIST SP 800-57/RFC 5480).
_EC_MIN_HASH = {
    "secp256r1": hashes.SHA256,
    "secp384r1": hashes.SHA384,
    "secp521r1": hashes.SHA512,
}
_HASH_RANK = {"sha256": 1, "sha384": 2, "sha512": 3}


class KeyAlgError(ValueError):
    """Spec thuật toán không hợp lệ / không hỗ trợ."""


def hash_from_name(name, default: str = "SHA256"):
    """'SHA256'/'SHA-384'/... → đối tượng hashes.HashAlgorithm. Fallback SHA256."""
    key = str(name or default).upper().replace("-", "")
    cls = _HASHES.get(key) or _HASHES[default]
    return cls()


def _normalize_spec(spec) -> str:
    """int (RSA bit, legacy) hoặc string spec → spec chuẩn hoá uppercase."""
    if isinstance(spec, int):
        return f"RSA-{spec}"
    return str(spec or "RSA-2048").strip().upper().replace(" ", "")


def generate_key(spec):
    """
    Sinh private key theo `spec`.

      spec là int (RSA bit, legacy) hoặc string: 'RSA-2048', 'EC-P256',
      'EC-P384', 'Ed25519'. Raise KeyAlgError nếu không hợp lệ.
    """
    s = _normalize_spec(spec)
    if s.startswith("RSA"):
        digits = "".join(c for c in s if c.isdigit())
        size = int(digits) if digits else 2048
        if size not in RSA_KEY_SIZES:
            raise KeyAlgError(
                f"RSA key size không hợp lệ: {size}. Chọn 1 trong {RSA_KEY_SIZES}."
            )
        return rsa.generate_private_key(public_exponent=65537, key_size=size)
    if s in _EC_CURVES:
        return ec.generate_private_key(_EC_CURVES[s]())
    if s in ("ED25519", "EDDSA"):
        return ed25519.Ed25519PrivateKey.generate()
    raise KeyAlgError(f"Thuật toán không hỗ trợ: {spec!r}. Chọn 1 trong {ALGO_CHOICES}.")


def is_eddsa(key) -> bool:
    return isinstance(key, (
        ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey,
        ed448.Ed448PrivateKey, ed448.Ed448PublicKey,
    ))


def signing_algorithm(private_key, hash_algorithm=None):
    """
    Tham số `algorithm` truyền vào x509 builder .sign(private_key, algorithm):

      • Ed25519 / Ed448 → None (BẮT BUỘC — khóa Ed có hàm băm cố định bên trong).
      • RSA              → hash_algorithm (mặc định SHA-256 nếu None).
      • ECDSA            → hash_algorithm, nhưng ÉP LÊN tối thiểu bằng độ mạnh
                           đường cong (P-256→SHA-256, P-384→SHA-384) để hàm băm
                           không thành "mắt xích yếu". Cho phép hash MẠNH hơn;
                           chỉ coerce khi yếu hơn. Ràng buộc backend này đồng bộ
                           với UI (KeyAlgSelector) và áp dụng cho MỌI lần ký bằng
                           khóa EC — kể cả khi root EC ký cert con/CRL bằng
                           hash_algorithm toàn cục.

    cryptography tự bọc ECDSA(hash) cho khóa EC ở tầng builder, nên RSA và EC
    đều truyền cùng một HashAlgorithm.
    """
    if is_eddsa(private_key):
        return None
    chosen = hash_algorithm or hashes.SHA256()
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        min_cls = _EC_MIN_HASH.get(private_key.curve.name, hashes.SHA256)
        min_h = min_cls()
        if _HASH_RANK.get(chosen.name, 1) < _HASH_RANK.get(min_h.name, 1):
            return min_h   # ép lên mức tối thiểu của đường cong
    return chosen


def verify_with_public_key(public_key, signature, data, hash_algorithm):
    """
    Verify chữ ký theo đúng loại khóa. Raise InvalidSignature nếu sai.

      • RSA      → PKCS#1 v1.5 + hash.
      • ECDSA    → ec.ECDSA(hash)  (KHÔNG truyền hash trần — đó là bug cũ).
      • Ed25519  → verify(sig, data) thuần, bỏ qua hash.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
    elif is_eddsa(public_key):
        public_key.verify(signature, data)
    else:
        public_key.verify(signature, data, hash_algorithm)


def public_key_fingerprint(public_key) -> str:
    """
    SHA-256 (hex) của SubjectPublicKeyInfo (DER) — định danh ỔN ĐỊNH của một
    public key, độc lập subject/serial/định dạng chứa. Là NGUỒN SỰ THẬT DUY NHẤT
    để so khớp khóa: cùng keypair → cùng fingerprint, dù trích từ cert
    (cert.public_key()) hay từ public-key PEM của customer_keys.
    """
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def algorithm_label(key) -> str:
    """Nhãn ngắn lưu DB + hiển thị: 'RSA' / 'EC' / 'Ed25519' / 'Ed448'."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "EC"
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448"
    return type(key).__name__


def key_size_for(key) -> int:
    """Giá trị cho cột key_size (NOT NULL): RSA→bit, EC→curve bit, Ed→0."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return key.key_size
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return key.curve.key_size
    return 0


def describe(key) -> str:
    """Nhãn người đọc, vd 'RSA 2048-bit', 'ECDSA (secp384r1)', 'Ed25519'."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"RSA {key.key_size}-bit"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return f"ECDSA ({key.curve.name})"
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448"
    return type(key).__name__
