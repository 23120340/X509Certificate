"""
issuer.py
---------
Root CA của demo.

Trong mô hình mới (sau khi nâng cấp theo X509_DEMO_REVIEW.md):

  Root CA (self-signed)
      │
      ├── ký Server Certificate (mỗi server-cert có issuer = Root CA subject)
      └── ký CRL

  Trust Store của client
      └── chứa Root CA certificate

Module này chịu trách nhiệm:
  - Tạo / load Root CA (cert + private key).
  - Publish Root CA cert ra Trust Store để client có thể đọc.
"""

import os
import shutil
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ROOT_CA_COMMON_NAME = "X509 Demo Root CA"


def load_or_create_issuer(cert_path: str, key_path: str):
    """
    Load Root CA từ file nếu đã có; nếu chưa, tự sinh Root CA self-signed
    mới rồi ghi ra `cert_path` / `key_path`.

    Trả về (root_ca_cert, root_ca_key).

    Tên hàm giữ nguyên để các module khác không phải đổi import; vai trò
    của "issuer" giờ là Root CA trong mô hình Root CA + Trust Store.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert, key

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CA_COMMON_NAME),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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

    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    return cert, key


def publish_root_ca_to_trust_store(root_ca_cert, trust_store_dir: str) -> str:
    """
    Ghi Root CA cert vào thư mục Trust Store của client.

    Trả về đường dẫn file `root_ca.crt`. Client sẽ load file này để có
    public key dùng cho việc verify server cert (Bước 1) và verify CRL.
    """
    os.makedirs(trust_store_dir, exist_ok=True)
    out_path = os.path.join(trust_store_dir, "root_ca.crt")
    with open(out_path, "wb") as f:
        f.write(root_ca_cert.public_bytes(serialization.Encoding.PEM))
    return out_path


def load_trust_store(trust_store_dir: str):
    """
    Trả về list các Root CA cert trong trust store. Trust store đơn giản
    chỉ chứa 1 file `root_ca.crt`, nhưng API thiết kế để mở rộng cho
    nhiều Root CA về sau (giống Windows / browser).
    """
    if not os.path.isdir(trust_store_dir):
        return []
    trusted = []
    for fname in sorted(os.listdir(trust_store_dir)):
        if not fname.lower().endswith((".crt", ".pem")):
            continue
        fpath = os.path.join(trust_store_dir, fname)
        try:
            with open(fpath, "rb") as f:
                trusted.append(x509.load_pem_x509_certificate(f.read()))
        except Exception:
            # Bỏ qua file không phải PEM hợp lệ thay vì crash demo.
            continue
    return trusted
