"""
cert_generator.py
-----------------
Phần 1 của đề bài: Sinh cặp khóa RSA + Tạo chứng chỉ X.509 v3 tự ký.

Cấu hình các Extensions bắt buộc:
  - Basic Constraints
  - Key Usage
  - Subject Alternative Name (SAN)
  - CRL Distribution Points
  - Authority Information Access (OCSP URL)

Hỗ trợ sinh chứng chỉ đã hết hạn (expired=True) để mô phỏng Test Case 2.
"""

import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(key_size: int = 2048):
    """Sinh cặp khóa RSA (Public/Private)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key


def _build_san_list(names):
    """Chuyển danh sách tên (DNS hoặc IP) thành các GeneralName cho SAN."""
    san = []
    for name in names:
        try:
            ip = ipaddress.ip_address(name)
            san.append(x509.IPAddress(ip))
        except ValueError:
            san.append(x509.DNSName(name))
    return san


def create_self_signed_cert(
    private_key,
    common_name: str = "localhost",
    dns_names=None,
    ocsp_url: str = "http://localhost:8888/ocsp",
    crl_url: str = "http://localhost:8889/crl.pem",
    validity_days: int = 365,
    expired: bool = False,
):
    """
    Tạo một chứng chỉ X.509 v3 tự ký.

    Tham số:
        private_key  : khóa RSA để ký (đồng thời là khóa của subject vì self-signed).
        common_name  : CN trong Subject / Issuer.
        dns_names    : list các SAN (DNS name hoặc IP).
        ocsp_url     : URL dịch vụ OCSP sẽ được nhúng vào AIA extension.
        crl_url      : URL đến file CRL sẽ được nhúng vào CRL Distribution Points.
        validity_days: thời hạn hiệu lực (ngày).
        expired      : True -> tạo chứng chỉ đã hết hạn (để test case 2).

    Trả về: (certificate, serial_number)
    """
    if dns_names is None:
        dns_names = ["localhost", "127.0.0.1"]

    # Với Self-signed: Issuer == Subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Simulation"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)
    if expired:
        # Nằm trong quá khứ: từ 30 ngày trước đến 1 ngày trước -> đã hết hạn
        not_before = now - timedelta(days=30)
        not_after = now - timedelta(days=1)
    else:
        # Còn hiệu lực bình thường
        not_before = now - timedelta(minutes=1)
        not_after = now + timedelta(days=validity_days)

    serial_number = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        # --- Extensions quan trọng theo yêu cầu ---
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(_build_san_list(dns_names)),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )

    # Tự ký bằng chính private key
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    return certificate, serial_number


def save_cert_and_key(cert, private_key, cert_path: str, key_path: str):
    """Lưu certificate và private key ra file PEM."""
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def load_cert(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(key_path: str):
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
