"""
services/cert_lifecycle.py
--------------------------
Quản lý vòng đời của cert đã phát hành — đáp ứng:
  • A.8  Admin quản lý các cert đã cấp phát (revoke, renew).
  • B.6  Customer xem danh sách + tải các cert đã được cấp.

API:
  • list_certs_for_owner(owner_id, db_path, status?)  — customer xem cert mình
  • list_all_certs(db_path, status?)                  — admin xem tất cả
  • get_cert_detail(cert_id, db_path, owner_id?)      — kèm cert_pem; nếu
                                                          owner_id != None
                                                          → enforce ownership
  • revoke_cert(cert_id, admin_id, reason, db_path)   — set revoked_at + reason
  • renew_cert(cert_id, admin_id, validity_days, db_path) → cert mới

Cert status được suy ra động (không lưu trong DB):
  revoked   → nếu revoked_at IS NOT NULL
  expired   → nếu now > not_valid_after
  active    → ngược lại
"""

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from core.cert_builder import reissue_cert_for_renewal
from db.connection import conn_scope, transaction
from services.ca_admin import load_active_root_ca_with_key, CAError


VALID_STATUS_FILTERS = ("active", "expired", "revoked", "all")
MAX_REVOKE_REASON_LEN = 500


class CertLifecycleError(Exception):
    """Lỗi nghiệp vụ trong cert lifecycle."""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _compute_status(row, now: datetime) -> str:
    """Suy ra status hiện tại của cert. Row phải có revoked_at + not_valid_after."""
    if row["revoked_at"]:
        return "revoked"
    na = _parse_iso(row["not_valid_after"])
    if na is None:
        return "active"
    # `not_valid_after` đã lưu dạng tz-aware; nếu không, gán UTC.
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)
    if na < now:
        return "expired"
    return "active"


def _row_to_dict(row, now: datetime) -> dict:
    d = dict(row)
    d["status"] = _compute_status(row, now)
    return d


# ── Queries ──────────────────────────────────────────────────────────────────

def _list_certs(db_path: str, where: str, params: tuple,
                status: Optional[str]) -> "list[dict]":
    """Helper chung: chạy query rồi filter status post-hoc (status là computed)."""
    if status is not None and status not in VALID_STATUS_FILTERS:
        raise CertLifecycleError(f"Status filter không hợp lệ: {status}")

    sql = (
        "SELECT c.id, c.csr_request_id, c.owner_id, u.username AS owner_username, "
        "       c.serial_hex, c.common_name, c.not_valid_before, "
        "       c.not_valid_after, c.issued_at, c.issued_by, "
        "       c.renewed_from_id, c.revoked_at, c.revocation_reason "
        "FROM issued_certs c LEFT JOIN users u ON u.id = c.owner_id"
    )
    if where:
        sql += " WHERE " + where
    sql += " ORDER BY c.id DESC"

    now = datetime.now(timezone.utc)
    with conn_scope(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        out: "list[dict]" = []
        for r in rows:
            d = _row_to_dict(r, now)
            if status in (None, "all") or d["status"] == status:
                out.append(d)
        return out


def list_certs_for_owner(
    owner_id: int, db_path: str, status: Optional[str] = None,
) -> "list[dict]":
    """Customer xem cert của mình (newest first)."""
    return _list_certs(db_path, "c.owner_id = ?", (owner_id,), status)


def list_all_certs(
    db_path: str, status: Optional[str] = None,
) -> "list[dict]":
    """Admin xem tất cả cert (newest first)."""
    return _list_certs(db_path, "", (), status)


def get_cert_detail(
    cert_id: int, db_path: str, owner_id: Optional[int] = None,
) -> Optional[dict]:
    """
    Trả về cert metadata + cert_pem. Nếu `owner_id != None`, enforce
    ownership (customer view). Trả về None nếu không tồn tại hoặc không
    thuộc owner_id.
    """
    sql = (
        "SELECT c.id, c.csr_request_id, c.owner_id, u.username AS owner_username, "
        "       c.serial_hex, c.common_name, c.cert_pem, "
        "       c.not_valid_before, c.not_valid_after, c.issued_at, "
        "       c.issued_by, c.renewed_from_id, "
        "       c.revoked_at, c.revocation_reason "
        "FROM issued_certs c LEFT JOIN users u ON u.id = c.owner_id "
        "WHERE c.id = ?"
    )
    params: tuple = (cert_id,)
    if owner_id is not None:
        sql += " AND c.owner_id = ?"
        params = (cert_id, owner_id)

    with conn_scope(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    return _row_to_dict(row, now)


# ── Revoke ───────────────────────────────────────────────────────────────────

def revoke_cert(
    cert_id: int, admin_id: int, reason: str, db_path: str,
) -> dict:
    """
    Đánh dấu cert đã thu hồi. CRL chưa publish ngay; sẽ snapshot qua
    services/crl_publish.py ở M8.

    Refuse nếu cert đã revoked rồi (giữ history chỉ 1 revocation event).
    Trả về dict cert sau khi revoke.
    """
    reason = (reason or "").strip()
    if not reason:
        raise CertLifecycleError("Lý do thu hồi không được rỗng.")
    if len(reason) > MAX_REVOKE_REASON_LEN:
        raise CertLifecycleError(
            f"Lý do dài quá {MAX_REVOKE_REASON_LEN} ký tự."
        )

    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT revoked_at FROM issued_certs WHERE id = ?", (cert_id,),
        ).fetchone()
        if row is None:
            raise CertLifecycleError("Không tìm thấy cert.")
        if row["revoked_at"]:
            raise CertLifecycleError(
                f"Cert đã bị revoked lúc {row['revoked_at']}."
            )
        conn.execute(
            "UPDATE issued_certs SET revoked_at = ?, revocation_reason = ? "
            "WHERE id = ?",
            (now, reason, cert_id),
        )

    detail = get_cert_detail(cert_id, db_path)
    return detail


# ── Renew ────────────────────────────────────────────────────────────────────

def renew_cert(
    cert_id: int,
    admin_id: int,
    validity_days: int,
    db_path: str,
    ocsp_url: str = "http://localhost:8888/ocsp",
    crl_url:  str = "http://localhost:8889/crl.pem",
) -> dict:
    """
    Phát hành cert MỚI giữ nguyên subject + public_key của cert cũ.
    Cert cũ KHÔNG bị revoke tự động — admin có thể revoke riêng nếu cần.

    Raise CertLifecycleError nếu:
      • cert_id không tồn tại
      • cert cũ đã revoked (renew cert đã thu hồi vô nghĩa)
      • chưa có Root CA active
    """
    if validity_days < 1:
        raise CertLifecycleError("validity_days phải >= 1.")

    old = get_cert_detail(cert_id, db_path)
    if old is None:
        raise CertLifecycleError("Không tìm thấy cert.")
    if old["revoked_at"]:
        raise CertLifecycleError(
            "Cert đã bị thu hồi — không thể renew. Phát hành cert mới qua CSR."
        )

    try:
        ca_cert, ca_key = load_active_root_ca_with_key(db_path)
    except CAError as e:
        raise CertLifecycleError(
            f"Không renew được: {e} Tạo Root CA trước."
        ) from e

    old_cert_obj = x509.load_pem_x509_certificate(bytes(old["cert_pem"]))
    new_cert, new_serial = reissue_cert_for_renewal(
        old_cert_obj, ca_cert, ca_key,
        validity_days=validity_days,
        ocsp_url=ocsp_url, crl_url=crl_url,
    )
    cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)

    try:
        nb = new_cert.not_valid_before_utc.isoformat()
        na = new_cert.not_valid_after_utc.isoformat()
    except AttributeError:
        nb = new_cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
        na = new_cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

    now = datetime.now(timezone.utc).isoformat()
    serial_hex = f"{new_serial:x}"

    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO issued_certs "
            "(csr_request_id, owner_id, serial_hex, common_name, cert_pem, "
            " not_valid_before, not_valid_after, issued_at, issued_by, "
            " renewed_from_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (old["csr_request_id"], old["owner_id"], serial_hex,
             old["common_name"], cert_pem, nb, na, now, admin_id, cert_id),
        )
        new_id = cur.lastrowid

    return {
        "id":                new_id,
        "csr_request_id":    old["csr_request_id"],
        "owner_id":          old["owner_id"],
        "serial_hex":        serial_hex,
        "common_name":       old["common_name"],
        "not_valid_before":  nb,
        "not_valid_after":   na,
        "issued_at":         now,
        "issued_by":         admin_id,
        "renewed_from_id":   cert_id,
        "status":            "active",
    }
