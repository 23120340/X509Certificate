"""
services/external_certs.py
--------------------------
B.9 — Customer upload chứng chỉ X.509 bất kỳ (không phải của mình) để theo
dõi + xem thông tin + chạy 5 bước verify.

API:
  • save_external_cert(uploader_id, pem_or_der, notes, db_path) → dict
        Parse cert, tính SHA-256 fingerprint, lưu vào `external_certs`.
        Reject nếu không parse được. Fingerprint UNIQUE per uploader để
        tránh upload trùng lặp.
  • list_external_certs(uploader_id, db_path) → list[dict]
  • get_external_cert(cert_id, uploader_id, db_path) → dict | None
        BOLA guard — chỉ uploader xem được cert của mình.
  • delete_external_cert(cert_id, uploader_id, db_path) → None
  • parse_cert_summary(pem_bytes) → dict
        Trả về metadata không lưu DB (cho preview trước khi save).
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509

from db.connection import conn_scope, transaction


MAX_NOTES_LEN = 500


class ExternalCertError(Exception):
    pass


def _parse_cert(data: bytes) -> "x509.Certificate":
    """PEM hoặc DER → Certificate object."""
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as e:
        raise ExternalCertError(f"Không parse được cert: {e}") from e


def _fingerprint_sha256(cert: "x509.Certificate") -> str:
    """SHA-256 của DER-encoded cert."""
    from cryptography.hazmat.primitives.serialization import Encoding
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def parse_cert_summary(data: bytes) -> dict:
    """
    Parse cert, trả metadata để preview trước khi lưu. Không animals DB.
    """
    cert = _parse_cert(data)
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before
        na = cert.not_valid_after
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        san_dns = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_dns = []
    pk = cert.public_key()
    pk_info = pk.__class__.__name__
    if hasattr(pk, "key_size"):
        pk_info += f" {pk.key_size} bits"
    return {
        "fingerprint_sha256": _fingerprint_sha256(cert),
        "subject":            cert.subject.rfc4514_string(),
        "issuer":             cert.issuer.rfc4514_string(),
        "serial_hex":         f"{cert.serial_number:x}",
        "not_valid_before":   nb.isoformat() if hasattr(nb, "isoformat") else str(nb),
        "not_valid_after":    na.isoformat() if hasattr(na, "isoformat") else str(na),
        "san_dns":            san_dns,
        "public_key":         pk_info,
    }


def save_external_cert(
    uploader_id: int,
    data: bytes,
    notes: str,
    db_path: str,
) -> dict:
    """
    Parse + lưu. Tự convert sang PEM bytes để DB chỉ chứa 1 format.
    Reject nếu cùng uploader đã upload cert có cùng fingerprint.
    """
    notes = (notes or "").strip()
    if len(notes) > MAX_NOTES_LEN:
        raise ExternalCertError(
            f"Notes dài quá {MAX_NOTES_LEN} ký tự."
        )
    cert = _parse_cert(data)
    from cryptography.hazmat.primitives.serialization import Encoding
    pem_bytes = cert.public_bytes(Encoding.PEM)
    fp = _fingerprint_sha256(cert)
    now = datetime.now(timezone.utc).isoformat()

    with transaction(db_path) as conn:
        dup = conn.execute(
            "SELECT id FROM external_certs "
            "WHERE uploader_id = ? AND fingerprint_sha256 = ?",
            (uploader_id, fp),
        ).fetchone()
        if dup:
            raise ExternalCertError(
                f"Bạn đã upload cert có fingerprint này trước đó "
                f"(record #{dup['id']})."
            )
        cur = conn.execute(
            "INSERT INTO external_certs "
            "(uploader_id, cert_pem, fingerprint_sha256, notes, uploaded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (uploader_id, pem_bytes, fp, notes or None, now),
        )
        new_id = cur.lastrowid

    return {
        "id":                  new_id,
        "uploader_id":         uploader_id,
        "fingerprint_sha256":  fp,
        "notes":               notes,
        "uploaded_at":         now,
        "subject":             cert.subject.rfc4514_string(),
        "issuer":              cert.issuer.rfc4514_string(),
        "serial_hex":          f"{cert.serial_number:x}",
    }


def list_external_certs(uploader_id: int, db_path: str) -> "list[dict]":
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT id, fingerprint_sha256, notes, uploaded_at, cert_pem "
            "FROM external_certs WHERE uploader_id = ? "
            "ORDER BY id DESC",
            (uploader_id,),
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            d = dict(r)
            # Thêm subject + issuer + validity từ cert_pem (parse on demand)
            try:
                summary = parse_cert_summary(bytes(r["cert_pem"]))
                d["subject"] = summary["subject"]
                d["issuer"]  = summary["issuer"]
                d["serial_hex"] = summary["serial_hex"]
                d["not_valid_after"] = summary["not_valid_after"]
            except ExternalCertError:
                d["subject"] = "?"
                d["issuer"] = "?"
                d["serial_hex"] = ""
                d["not_valid_after"] = ""
            out.append(d)
        return out


def get_external_cert(
    cert_id: int, uploader_id: int, db_path: str,
) -> Optional[dict]:
    """BOLA-guarded — chỉ uploader xem được."""
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT id, uploader_id, cert_pem, fingerprint_sha256, "
            "       notes, uploaded_at FROM external_certs "
            "WHERE id = ? AND uploader_id = ?",
            (cert_id, uploader_id),
        ).fetchone()
        return dict(row) if row else None


def delete_external_cert(
    cert_id: int, uploader_id: int, db_path: str,
) -> None:
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM external_certs "
            "WHERE id = ? AND uploader_id = ?",
            (cert_id, uploader_id),
        ).fetchone()
        if row is None:
            raise ExternalCertError("Không tìm thấy cert (hoặc không thuộc bạn).")
        conn.execute(
            "DELETE FROM external_certs WHERE id = ? AND uploader_id = ?",
            (cert_id, uploader_id),
        )
