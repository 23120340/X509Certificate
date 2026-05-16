"""
services/csr_admin.py
---------------------
Admin side của CSR workflow (đáp ứng A.6 từ chối + A.7 phê duyệt CSR).

API:
  • list_pending_csr(db_path)          — queue CSR chờ duyệt (newest first)
  • list_all_csr(db_path, status?)     — tất cả CSR có thể filter status
  • get_csr_detail(csr_id, db_path)    — đầy đủ thông tin (KHÔNG check ownership
                                          vì admin được phép xem mọi CSR)
  • reject_csr(csr_id, admin_id, reason, db_path)
  • approve_csr(csr_id, admin_id, validity_days, db_path) → issued_cert dict

approve_csr là transaction chính:
  1. Load CSR row, check status == 'pending'.
  2. Parse CSR PEM, verify chữ ký CSR (proof of possession).
  3. Load Root CA active (decrypt private key).
  4. Build cert end-entity từ CSR + ký bằng Root CA key.
  5. INSERT issued_certs + UPDATE csr_requests status='approved'.
  6. Return cert info.
Tất cả bước DB nằm trong 1 transaction → atomic.
"""

from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import serialization

from core.cert_builder import issue_cert_from_csr
from core.csr import parse_csr, verify_csr_signature
from db.connection import conn_scope, transaction
from services.ca_admin import load_active_root_ca_with_key, CAError


# Default URLs cho CRL Distribution Points + AIA OCSP trong cert phát hành.
# Khớp với legacy demo + sẽ thành config trong system_config ở M8.
DEFAULT_CRL_URL  = "http://localhost:8889/crl.pem"
DEFAULT_OCSP_URL = "http://localhost:8888/ocsp"

MAX_REJECT_REASON_LEN = 500
ALLOWED_STATUS = ("pending", "approved", "rejected")


class CSRAdminError(Exception):
    """Lỗi nghiệp vụ trong CSR admin workflow."""


# ── Queries ──────────────────────────────────────────────────────────────────

def list_pending_csr(db_path: str) -> "list[dict]":
    """Danh sách CSR pending — newest first."""
    return list_all_csr(db_path, status="pending")


def list_all_csr(db_path: str, status: Optional[str] = None) -> "list[dict]":
    """Tất cả CSR. Có thể filter theo status."""
    if status is not None and status not in ALLOWED_STATUS:
        raise CSRAdminError(f"Status không hợp lệ: {status}")

    sql = (
        "SELECT c.id, c.requester_id, u.username AS requester_username, "
        "       c.customer_key_id, c.common_name, c.san_list_json, "
        "       c.status, c.reject_reason, c.submitted_at, c.reviewed_at, "
        "       c.reviewed_by "
        "FROM csr_requests c "
        "LEFT JOIN users u ON u.id = c.requester_id "
    )
    params: list = []
    if status:
        sql += "WHERE c.status = ? "
        params.append(status)
    sql += "ORDER BY c.id DESC"

    import json as _json
    with conn_scope(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        out: list[dict] = []
        for r in rows:
            d = dict(r)
            d["san_list"] = (
                _json.loads(d.pop("san_list_json")) if d.get("san_list_json") else []
            )
            out.append(d)
        return out


def get_csr_detail(csr_id: int, db_path: str) -> Optional[dict]:
    """Chi tiết CSR bao gồm PEM. Admin được xem mọi CSR."""
    import json as _json
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT c.id, c.requester_id, u.username AS requester_username, "
            "       c.customer_key_id, c.common_name, c.san_list_json, "
            "       c.csr_pem, c.status, c.reject_reason, "
            "       c.submitted_at, c.reviewed_at, c.reviewed_by "
            "FROM csr_requests c "
            "LEFT JOIN users u ON u.id = c.requester_id "
            "WHERE c.id = ?",
            (csr_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["san_list"] = (
            _json.loads(d.pop("san_list_json")) if d.get("san_list_json") else []
        )
        return d


# ── Reject ───────────────────────────────────────────────────────────────────

def reject_csr(
    csr_id: int, admin_id: int, reason: str, db_path: str,
) -> None:
    """Đặt CSR sang rejected với reason. CSR phải đang pending."""
    reason = (reason or "").strip()
    if not reason:
        raise CSRAdminError("Lý do từ chối không được rỗng.")
    if len(reason) > MAX_REJECT_REASON_LEN:
        raise CSRAdminError(
            f"Lý do dài quá {MAX_REJECT_REASON_LEN} ký tự."
        )

    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM csr_requests WHERE id = ?", (csr_id,),
        ).fetchone()
        if row is None:
            raise CSRAdminError("Không tìm thấy CSR.")
        if row["status"] != "pending":
            raise CSRAdminError(
                f"CSR đang ở status '{row['status']}', không reject được."
            )
        conn.execute(
            "UPDATE csr_requests SET status = 'rejected', "
            "    reject_reason = ?, reviewed_at = ?, reviewed_by = ? "
            "WHERE id = ?",
            (reason, now, admin_id, csr_id),
        )


# ── Approve + issue cert ─────────────────────────────────────────────────────

def approve_csr(
    csr_id: int,
    admin_id: int,
    validity_days: int,
    db_path: str,
    ocsp_url: str = DEFAULT_OCSP_URL,
    crl_url:  str = DEFAULT_CRL_URL,
) -> dict:
    """
    Phê duyệt CSR + phát hành cert.

    Raise CSRAdminError nếu:
      • CSR không tồn tại / không pending
      • Chữ ký CSR không hợp lệ (CSR bị sửa hoặc keypair sai)
      • Chưa có Root CA active

    Trả về dict metadata của cert vừa phát hành.
    """
    if validity_days < 1:
        raise CSRAdminError("validity_days phải >= 1.")

    # Read CSR row trước (ngoài transaction) để load CA key + build cert
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT id, requester_id, common_name, csr_pem, status "
            "FROM csr_requests WHERE id = ?", (csr_id,),
        ).fetchone()
    if row is None:
        raise CSRAdminError("Không tìm thấy CSR.")
    if row["status"] != "pending":
        raise CSRAdminError(
            f"CSR đang ở status '{row['status']}', không approve được."
        )

    # Parse + verify CSR (proof of possession)
    csr_pem = bytes(row["csr_pem"])
    try:
        csr_obj = parse_csr(csr_pem)
    except ValueError as e:
        raise CSRAdminError(f"CSR PEM không hợp lệ: {e}") from e
    if not verify_csr_signature(csr_obj):
        raise CSRAdminError(
            "Chữ ký CSR không hợp lệ — có thể bị sửa hoặc khớp sai keypair. "
            "Từ chối phát hành."
        )

    # Load Root CA active
    try:
        ca_cert, ca_key = load_active_root_ca_with_key(db_path)
    except CAError as e:
        raise CSRAdminError(
            f"Không phát hành được cert: {e} Tạo Root CA trước."
        ) from e

    # Build + sign cert
    cert, serial_number = issue_cert_from_csr(
        csr_obj, ca_cert, ca_key,
        validity_days=validity_days,
        ocsp_url=ocsp_url, crl_url=crl_url,
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    try:
        nb = cert.not_valid_before_utc.isoformat()
        na = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
        na = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

    now = datetime.now(timezone.utc).isoformat()
    serial_hex = f"{serial_number:x}"

    with transaction(db_path) as conn:
        # Re-check status trong transaction (chống race: 2 admin approve cùng lúc)
        cur_status = conn.execute(
            "SELECT status FROM csr_requests WHERE id = ?", (csr_id,),
        ).fetchone()
        if cur_status is None or cur_status["status"] != "pending":
            raise CSRAdminError(
                "CSR đã được xử lý bởi admin khác. Hủy approve."
            )

        cur = conn.execute(
            "INSERT INTO issued_certs "
            "(csr_request_id, owner_id, serial_hex, common_name, cert_pem, "
            " not_valid_before, not_valid_after, issued_at, issued_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (csr_id, row["requester_id"], serial_hex, row["common_name"],
             cert_pem, nb, na, now, admin_id),
        )
        cert_id = cur.lastrowid

        conn.execute(
            "UPDATE csr_requests SET status = 'approved', "
            "    reviewed_at = ?, reviewed_by = ? "
            "WHERE id = ?",
            (now, admin_id, csr_id),
        )

    return {
        "id":               cert_id,
        "csr_request_id":   csr_id,
        "owner_id":         row["requester_id"],
        "serial_hex":       serial_hex,
        "common_name":      row["common_name"],
        "not_valid_before": nb,
        "not_valid_after":  na,
        "issued_at":        now,
        "issued_by":        admin_id,
        "validity_days":    validity_days,
    }
