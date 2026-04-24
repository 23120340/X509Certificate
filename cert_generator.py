"""
cert_generator.py
-----------------
PKI hierarchy (chỉ 2 tầng, không có Intermediate CA):

  CA Root  → self-signed, ký server certificate
  Server   → sinh key pair + CSR, nhận cert từ CA Root
"""

import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(key_size: int = 2048):
    """Sinh cặp khóa RSA (trả về private key, public key nằm bên trong)."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def generate_ca_root_cert(
    ca_key,
    common_name: str = "X509 Simulation Root CA",
    validity_days: int = 3650,
):
    """Tạo chứng chỉ CA Root tự ký (self-signed)."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Simulation"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)
    serial_number = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
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
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    certificate = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return certificate, serial_number


def generate_csr(server_key, common_name: str = "localhost", dns_names=None):
    """Server sinh Certificate Signing Request để gửi lên RA/CA."""
    if dns_names is None:
        dns_names = ["localhost", "127.0.0.1"]

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Simulation Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName(_build_san_list(dns_names)),
            critical=False,
        )
        .sign(server_key, hashes.SHA256())
    )
    return csr


def ca_sign_csr(
    csr,
    ca_cert,
    ca_key,
    ocsp_url: str = "http://localhost:8888/ocsp",
    crl_url: str = "http://localhost:8889/crl.pem",
    validity_days: int = 365,
    expired: bool = False,
):
    """CA Root ký CSR → trả về (server_certificate, serial_number)."""
    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=30)
        not_after = now - timedelta(days=1)
    else:
        not_before = now - timedelta(minutes=1)
        not_after = now + timedelta(days=validity_days)

    serial_number = x509.random_serial_number()

    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = san_ext.value
    except x509.ExtensionNotFound:
        san_value = x509.SubjectAlternativeName(_build_san_list(["localhost", "127.0.0.1"]))

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(san_value, critical=False)
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
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    certificate = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return certificate, serial_number


def _build_san_list(names):
    san = []
    for name in names:
        try:
            ip = ipaddress.ip_address(name)
            san.append(x509.IPAddress(ip))
        except ValueError:
            san.append(x509.DNSName(name))
    return san


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


def save_cert(cert, cert_path: str):
    """Lưu chỉ certificate ra file PEM."""
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(key_path: str):
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
