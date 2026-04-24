"""
cert_generator.py
-----------------
Sinh cặp khóa RSA + tạo chứng chỉ X.509 v3 self-signed cho từng server.

Mỗi server tự ký cert bằng private key của chính nó
(issuer == subject, signature dùng server's own key).
"""

import base64
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(key_size: int = 2048):
    """Sinh cặp khóa RSA. Trả về private key (public key nằm bên trong)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


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
    Tạo chứng chỉ X.509 v3 self-signed.
    issuer == subject, cert được ký bằng chính private_key truyền vào.
    """
    if dns_names is None:
        dns_names = ["localhost", "127.0.0.1"]

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=30)
        not_after  = now - timedelta(days=1)
    else:
        not_before = now - timedelta(minutes=1)
        not_after  = now + timedelta(days=validity_days)

    serial_number = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
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
                    relative_name=None, reasons=None, crl_issuer=None,
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

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    return certificate, serial_number


def tamper_cert_pem(pem_bytes: bytes) -> bytes:
    """
    Lật 1 bit trong vùng chữ ký của cert (không thay đổi cấu trúc ASN.1).
    Cert vẫn parse được nhưng verify_signature sẽ raise InvalidSignature.
    """
    cert = x509.load_pem_x509_certificate(pem_bytes)
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))

    # Chữ ký RSA-2048 nằm ở cuối DER (256 bytes).
    # Lật byte ở vị trí -50 → chắc chắn trong phần signature value.
    der[-50] ^= 0x01

    new_b64 = base64.b64encode(bytes(der)).decode()
    wrapped = "\n".join(new_b64[i:i+64] for i in range(0, len(new_b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n".encode()


def _build_san_list(names):
    san = []
    for name in names:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            san.append(x509.DNSName(name))
    return san


def save_cert_and_key(cert, private_key, cert_path: str, key_path: str):
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))


def save_cert(cert, cert_path: str):
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(key_path: str):
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
