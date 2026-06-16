"""
core/cert_builder.py
--------------------
Sinh cặp khóa RSA + tạo chứng chỉ X.509 v3.

Có hai chế độ tạo cert:

  1. create_self_signed_cert(...)            – cert tự ký (giữ cho khả năng demo
                                                cũ hoặc các test legacy).
  2. create_server_cert_signed_by_ca(...)    – cert SERVER được Root CA ký.
                                                Đây là cách dùng chính của demo
                                                sau khi nâng cấp theo mô hình
                                                Root CA + Trust Store.
"""

import base64
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core import keyalg


def generate_rsa_keypair(key_size: int = 2048):
    """Sinh cặp khóa RSA. Trả về private key (public key nằm bên trong)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _tls_server_key_usage(public_key) -> x509.KeyUsage:
    """
    KeyUsage cho TLS server end-entity cert. `key_encipherment` chỉ có nghĩa
    với RSA (RSA key transport); với khóa ECDSA/Ed25519 (chỉ ký) phải TẮT bit
    này để cert đúng về mặt ngữ nghĩa. `digital_signature` luôn bật.
    """
    return x509.KeyUsage(
        digital_signature=True,
        key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
        content_commitment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )


def _server_subject(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def create_server_cert_signed_by_ca(
    server_private_key,
    ca_cert,
    ca_private_key,
    common_name: str = "localhost",
    dns_names=None,
    ocsp_url: "str | None" = None,
    crl_url: "str | None" = None,
    validity_days: int = 365,
    expired: bool = False,
    hash_algorithm=None,
):
    """
    Tạo chứng chỉ X.509 v3 cho server, KÝ bằng Root CA.

    issuer = ca_cert.subject
    subject = CN=<common_name>
    Chữ ký được tạo bằng ca_private_key của Root CA.

    Server cert KHÔNG còn là CA: BasicConstraints(ca=False).
    Thêm Extended Key Usage = serverAuth cho đúng vai trò TLS server cert.

    URLs mặc định lấy từ `services.infra_manager` để tự động khớp với port
    server thực tế (kể cả khi user override qua env PROD_*_PORT).
    """
    if dns_names is None:
        dns_names = ["localhost", "127.0.0.1"]
    if ocsp_url is None:
        from services.infra_manager import prod_ocsp_url
        ocsp_url = prod_ocsp_url()
    if crl_url is None:
        from services.infra_manager import prod_crl_url
        crl_url = prod_crl_url()

    subject = _server_subject(common_name)
    issuer = ca_cert.subject

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
        .public_key(server_private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            _tls_server_key_usage(server_private_key.public_key()),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
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
            x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=keyalg.signing_algorithm(ca_private_key, hash_algorithm),
    )
    return certificate, serial_number


def create_self_signed_cert(
    private_key,
    common_name: str = "localhost",
    dns_names=None,
    ocsp_url: "str | None" = None,
    crl_url: "str | None" = None,
    validity_days: int = 365,
    expired: bool = False,
    hash_algorithm=None,
):
    """
    LEGACY: Tạo chứng chỉ X.509 v3 self-signed (issuer == subject).
    Giữ lại cho các test legacy. Demo chính dùng
    `create_server_cert_signed_by_ca`.
    """
    if dns_names is None:
        dns_names = ["localhost", "127.0.0.1"]
    if ocsp_url is None:
        from services.infra_manager import prod_ocsp_url
        ocsp_url = prod_ocsp_url()
    if crl_url is None:
        from services.infra_manager import prod_crl_url
        crl_url = prod_crl_url()

    subject = issuer = _server_subject(common_name)

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

    certificate = builder.sign(
        private_key=private_key,
        algorithm=keyalg.signing_algorithm(private_key, hash_algorithm),
    )
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


def _build_end_entity_cert(
    subject_name,
    public_key,
    san_value,
    ca_cert,
    ca_private_key,
    validity_days: int,
    ocsp_url: str,
    crl_url: str,
    hash_algorithm=None,
):
    """
    Internal helper — build cert end-entity với 1 cấu hình extensions cố định
    (TLS server cert). Dùng chung cho `issue_cert_from_csr` (M6) và
    `reissue_cert_for_renewal` (M7).

      • subject_name   = x509.Name (subject của cert)
      • public_key     = key sẽ được embed vào cert
      • san_value      = x509.SubjectAlternativeName hoặc None
      • ca_cert/ca_key = Root CA (signer)
    """
    now = datetime.now(timezone.utc)
    serial_number = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            _tls_server_key_usage(public_key),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    if san_value is not None:
        builder = builder.add_extension(san_value, critical=False)

    builder = (
        builder
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
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(
        private_key=ca_private_key,
        algorithm=keyalg.signing_algorithm(ca_private_key, hash_algorithm),
    )
    return cert, serial_number


def _extract_san(cert_or_csr) -> "x509.SubjectAlternativeName | None":
    try:
        ext = cert_or_csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        return ext.value
    except x509.ExtensionNotFound:
        return None


def issue_cert_from_csr(
    csr,
    ca_cert,
    ca_private_key,
    validity_days: int = 365,
    ocsp_url: "str | None" = None,
    crl_url: "str | None"  = None,
    hash_algorithm=None,
):
    """
    Phát hành cert end-entity từ CSR đã được CSR-owner ký.

    Subject + public_key lấy từ CSR (proof of possession). SAN copy từ CSR
    nếu có. Caller chịu trách nhiệm verify chữ ký CSR TRƯỚC khi gọi hàm này
    (xem services/csr_admin.approve_csr).

    URLs mặc định = prod CRL/OCSP (auto-khớp env override). Lab inject URL
    riêng qua tham số.

    Trả về (cert, serial_number).
    """
    if ocsp_url is None:
        from services.infra_manager import prod_ocsp_url
        ocsp_url = prod_ocsp_url()
    if crl_url is None:
        from services.infra_manager import prod_crl_url
        crl_url = prod_crl_url()
    return _build_end_entity_cert(
        subject_name=csr.subject,
        public_key=csr.public_key(),
        san_value=_extract_san(csr),
        ca_cert=ca_cert, ca_private_key=ca_private_key,
        validity_days=validity_days,
        ocsp_url=ocsp_url, crl_url=crl_url,
        hash_algorithm=hash_algorithm,
    )


def reissue_cert_for_renewal(
    old_cert,
    ca_cert,
    ca_private_key,
    validity_days: int = 365,
    ocsp_url: "str | None" = None,
    crl_url: "str | None"  = None,
    hash_algorithm=None,
):
    """
    KÝ LẠI một chứng chỉ đã có với thời hạn MỚI. Dùng cho:
      • admin RENEW (A.8) — gia hạn cert tại chỗ, và
      • RE-ISSUE hàng loạt khi đổi/active Root CA mới.

    GIỮ NGUYÊN: subject, public key, và TOÀN BỘ extensions của cert cũ
    (BasicConstraints, KeyUsage, EKU, SAN, SubjectKeyIdentifier, CRLDP, AIA…).
    Chỉ thay đổi:
      • validity window mới (now-1p … now+validity_days),
      • serial number MỚI — X.509 bắt buộc serial duy nhất mỗi issuer,
      • AuthorityKeyIdentifier tính lại theo CA đang ký (phòng khi CA rotate),
      • chữ ký mới của Root CA active.

    KHÔNG đụng vào private key của customer (admin không có quyền). ocsp_url/
    crl_url: nếu truyền (khác None) sẽ GHI ĐÈ CRLDP/AIA bằng URL mới; None →
    giữ nguyên extension cũ.

    Trả về (cert, serial_number).
    """
    now = datetime.now(timezone.utc)
    new_serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(old_cert.subject)
        .issuer_name(ca_cert.subject)
        .public_key(old_cert.public_key())
        .serial_number(new_serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
    )

    # Copy lại từng extension của cert cũ, TRỪ AuthorityKeyIdentifier (tính lại
    # theo CA active) và CRLDP/AIA nếu caller muốn ghi đè URL mới.
    for ext in old_cert.extensions:
        val = ext.value
        if isinstance(val, x509.AuthorityKeyIdentifier):
            continue
        if ocsp_url is not None and isinstance(val, x509.AuthorityInformationAccess):
            continue
        if crl_url is not None and isinstance(val, x509.CRLDistributionPoints):
            continue
        builder = builder.add_extension(val, critical=ext.critical)

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
    if ocsp_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
    if crl_url is not None:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )

    cert = builder.sign(
        private_key=ca_private_key,
        algorithm=keyalg.signing_algorithm(ca_private_key, hash_algorithm),
    )
    return cert, new_serial


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
