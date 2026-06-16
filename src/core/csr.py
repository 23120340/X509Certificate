"""
core/csr.py
-----------
Certificate Signing Request (CSR) — chuẩn PKCS#10.

  build_csr(private_key, common_name, san_list)  → x509.CertificateSigningRequest
  parse_csr(pem_or_der: bytes)                    → x509.CertificateSigningRequest
  verify_csr_signature(csr)                        → bool
  csr_to_pem(csr)                                  → bytes

CSR có chữ ký của private key chủ nhân → đảm bảo "proof of possession":
admin khi duyệt CSR phải verify chữ ký này trước khi phát hành cert.
"""

import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from core import keyalg


def _build_san_list(names: "list[str]") -> "list[x509.GeneralName]":
    """Convert list string → list[GeneralName]. IP vs DNS auto-detect."""
    san: "list[x509.GeneralName]" = []
    for n in names:
        n = n.strip()
        if not n:
            continue
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            san.append(x509.DNSName(n))
    return san


def build_csr(
    private_key,
    common_name: str,
    san_list: "list[str] | None" = None,
    organization: str = "X509 Demo",
    country: str = "VN",
    hash_algorithm=None,
) -> x509.CertificateSigningRequest:
    """
    Tạo CSR cho website, ký bởi `private_key` chủ nhân.

    `common_name` là tên miền (vd "example.com"). Nếu `san_list` rỗng/None,
    tự thêm `common_name` vào SAN — chuẩn TLS hiện đại yêu cầu hostname
    phải nằm trong SAN, không chỉ CN.

    Hỗ trợ private_key RSA / ECDSA / Ed25519 — thuật toán ký được suy ra theo
    loại khóa (Ed25519 không dùng hàm băm ngoài).
    """
    if not common_name or not common_name.strip():
        raise ValueError("common_name không được rỗng")
    common_name = common_name.strip()

    san_values = list(san_list or [])
    if common_name not in san_values:
        san_values.insert(0, common_name)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,      country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME,       common_name),
    ])

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName(_build_san_list(san_values)),
            critical=False,
        )
    )
    return builder.sign(
        private_key, keyalg.signing_algorithm(private_key, hash_algorithm)
    )


def parse_csr(data: bytes) -> x509.CertificateSigningRequest:
    """Parse CSR từ PEM hoặc DER bytes. Raise ValueError nếu không hợp lệ."""
    try:
        return x509.load_pem_x509_csr(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_csr(data)
    except ValueError as e:
        raise ValueError(f"Không parse được CSR: {e}") from e


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """
    Verify chữ ký CSR bằng public key trong chính CSR (proof of possession).
    Trả về True nếu OK.
    """
    # cryptography >= 40 có CSR.is_signature_valid (xử lý đúng mọi loại khóa).
    if hasattr(csr, "is_signature_valid"):
        return bool(csr.is_signature_valid)
    # Fallback: verify thủ công theo đúng loại khóa (RSA/ECDSA/Ed25519).
    try:
        keyalg.verify_with_public_key(
            csr.public_key(), csr.signature,
            csr.tbs_certrequest_bytes, csr.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def get_csr_common_name(csr: x509.CertificateSigningRequest) -> str:
    """Trả về CN trong CSR subject, hoặc '' nếu không có."""
    attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def get_csr_san_dns(csr: x509.CertificateSigningRequest) -> "list[str]":
    """Trả về list DNSName trong SAN extension, rỗng nếu không có."""
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))
