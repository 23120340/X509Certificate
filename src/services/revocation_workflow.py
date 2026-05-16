"""
services/revocation_workflow.py
-------------------------------
Workflow yêu cầu thu hồi cert — đáp ứng:
  • B.7  Customer yêu cầu thu hồi cert của mình.
  • A.9  Admin duyệt yêu cầu thu hồi (approve / reject).

API:
  • submit_revoke_request(cert_id, requester_id, reason, db_path)
      — Customer: tạo request mới. Validate ownership + cert chưa revoked +
        chưa có request pending.
  • list_my_revocation_requests(requester_id, db_path)
  • list_pending_revocations(db_path)        — admin queue
  • list_all_revocations(db_path, status?)    — admin xem tất cả
  • get_revocation_detail(req_id, db_path)
  • approve_revocation(req_id, admin_id, db_path)
      — Admin approve: trong cùng 1 transaction, set request='approved' +
        UPDATE issued_certs.revoked_at + revocation_reason. Nếu cert đã bị
        revoke bởi đường khác (admin revoke trực tiếp ở M7) thì vẫn approve
        request nhưng KHÔNG ghi đè revoked_at.
  • reject_revocation(req_id, admin_id, reason, db_path)

approve_revocation atomic — chống race 2 admin cùng duyệt.
"""

from datetime import datetime, timezone
from typing import Optional

from db.connection import conn_scope, transaction


MAX_REASON_LEN = 500
VALID_STATUS = ("pending", "approved", "rejected")


class RevocationWorkflowError(Exception):
    pass


# ── Submit (customer side) ───────────────────────────────────────────────────

def submit_revoke_request(
    cert_id: int, requester_id: int, reason: str, db_path: str,
) -> dict:
    """
    Customer gửi yêu cầu thu hồi cert của mình. Validate:
      • cert tồn tại + thuộc requester_id (BOLA guard)
      • cert chưa revoked
      • cert chưa có request pending nào khác
      • reason không rỗng (max MAX_REASON_LEN ký tự)
    """
    reason = (reason or "").strip()
    if not reason:
        raise RevocationWorkflowError("Lý do thu hồi không được rỗng.")
    if len(reason) > MAX_REASON_LEN:
        raise RevocationWorkflowError(
            f"Lý do dài quá {MAX_REASON_LEN} ký tự."
        )

    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        cert = conn.execute(
            "SELECT id, owner_id, revoked_at, common_name "
            "FROM issued_certs WHERE id = ?", (cert_id,),
        ).fetchone()
        if cert is None or cert["owner_id"] != requester_id:
            raise RevocationWorkflowError(
                f"Cert id={cert_id} không tồn tại hoặc không thuộc về bạn."
            )
        if cert["revoked_at"]:
            raise RevocationWorkflowError(
                "Cert đã bị thu hồi rồi, không cần gửi yêu cầu."
            )

        # Check pending request đã có chưa
        dup = conn.execute(
            "SELECT id FROM revocation_requests "
            "WHERE issued_cert_id = ? AND status = 'pending'",
            (cert_id,),
        ).fetchone()
        if dup:
            raise RevocationWorkflowError(
                f"Đã có yêu cầu thu hồi pending cho cert này (request #{dup['id']})."
            )

        cur = conn.execute(
            "INSERT INTO revocation_requests "
            "(issued_cert_id, requester_id, reason, status, submitted_at) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (cert_id, requester_id, reason, now),
        )
        req_id = cur.lastrowid

    return {
        "id":             req_id,
        "issued_cert_id": cert_id,
        "requester_id":   requester_id,
        "reason":         reason,
        "status":         "pending",
        "submitted_at":   now,
    }


# ── Queries ──────────────────────────────────────────────────────────────────

def _join_query(where: str, params: tuple) -> str:
    """SQL chung kèm JOIN ra cert + user info."""
    sql = (
        "SELECT r.id, r.issued_cert_id, r.requester_id, "
        "       u.username AS requester_username, "
        "       r.reason, r.status, r.submitted_at, r.reviewed_at, r.reviewed_by, "
        "       ic.serial_hex, ic.common_name, ic.revoked_at AS cert_revoked_at "
        "FROM revocation_requests r "
        "LEFT JOIN users u ON u.id = r.requester_id "
        "LEFT JOIN issued_certs ic ON ic.id = r.issued_cert_id"
    )
    if where:
        sql += " WHERE " + where
    sql += " ORDER BY r.id DESC"
    return sql


def list_my_revocation_requests(
    requester_id: int, db_path: str,
) -> "list[dict]":
    """Customer xem các request của mình (newest first)."""
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            _join_query("r.requester_id = ?", (requester_id,)),
            (requester_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_pending_revocations(db_path: str) -> "list[dict]":
    """Queue admin: chỉ pending."""
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            _join_query("r.status = 'pending'", ()),
        ).fetchall()
        return [dict(r) for r in rows]


def list_all_revocations(
    db_path: str, status: Optional[str] = None,
) -> "list[dict]":
    """Admin xem tất cả; có thể filter."""
    if status is not None and status not in VALID_STATUS:
        raise RevocationWorkflowError(f"Status không hợp lệ: {status}")
    where = ""
    params: tuple = ()
    if status:
        where = "r.status = ?"
        params = (status,)
    with conn_scope(db_path) as conn:
        rows = conn.execute(_join_query(where, params), params).fetchall()
        return [dict(r) for r in rows]


def get_revocation_detail(req_id: int, db_path: str) -> Optional[dict]:
    """Chi tiết 1 request."""
    with conn_scope(db_path) as conn:
        row = conn.execute(
            _join_query("r.id = ?", (req_id,)), (req_id,),
        ).fetchone()
        return dict(row) if row else None


# ── Admin approve / reject ───────────────────────────────────────────────────

def approve_revocation(
    req_id: int, admin_id: int, db_path: str,
) -> dict:
    """
    Approve revocation request atomic:
      • UPDATE revocation_requests.status = 'approved'
      • UPDATE issued_certs.revoked_at + revocation_reason (nếu cert chưa
        bị revoke từ trước). Nếu đã revoke thì giữ nguyên revoked_at cũ
        (chỉ ghi nhận approve trong audit).

    Raise RevocationWorkflowError nếu:
      • Request không tồn tại
      • Request không ở status pending
    """
    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        req = conn.execute(
            "SELECT id, issued_cert_id, reason, status "
            "FROM revocation_requests WHERE id = ?", (req_id,),
        ).fetchone()
        if req is None:
            raise RevocationWorkflowError("Không tìm thấy request.")
        if req["status"] != "pending":
            raise RevocationWorkflowError(
                f"Request đang ở status '{req['status']}', không approve được."
            )

        cert = conn.execute(
            "SELECT id, revoked_at FROM issued_certs WHERE id = ?",
            (req["issued_cert_id"],),
        ).fetchone()
        if cert is None:
            raise RevocationWorkflowError(
                "Cert không tồn tại nữa — không thể approve."
            )

        # Set cert revoked nếu chưa
        if cert["revoked_at"] is None:
            conn.execute(
                "UPDATE issued_certs SET revoked_at = ?, "
                "    revocation_reason = ? WHERE id = ?",
                (now, req["reason"], cert["id"]),
            )
            cert_was_revoked = True
        else:
            cert_was_revoked = False

        # Set request approved
        conn.execute(
            "UPDATE revocation_requests SET status = 'approved', "
            "    reviewed_at = ?, reviewed_by = ? WHERE id = ?",
            (now, admin_id, req_id),
        )

    return {
        "id":               req_id,
        "issued_cert_id":   req["issued_cert_id"],
        "reviewed_at":      now,
        "reviewed_by":      admin_id,
        "cert_was_revoked": cert_was_revoked,
        "cert_revoked_at":  now if cert_was_revoked else cert["revoked_at"],
    }


def reject_revocation(
    req_id: int, admin_id: int, reason: str, db_path: str,
) -> None:
    """Admin từ chối request. Reason bắt buộc."""
    reason = (reason or "").strip()
    if not reason:
        raise RevocationWorkflowError(
            "Lý do từ chối không được rỗng."
        )
    if len(reason) > MAX_REASON_LEN:
        raise RevocationWorkflowError(
            f"Lý do dài quá {MAX_REASON_LEN} ký tự."
        )

    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM revocation_requests WHERE id = ?", (req_id,),
        ).fetchone()
        if row is None:
            raise RevocationWorkflowError("Không tìm thấy request.")
        if row["status"] != "pending":
            raise RevocationWorkflowError(
                f"Request đang ở status '{row['status']}', không reject được."
            )
        # Lưu lý do từ chối vào trường reason (append) để giữ history
        conn.execute(
            "UPDATE revocation_requests SET status = 'rejected', "
            "    reviewed_at = ?, reviewed_by = ?, "
            "    reason = reason || ' || REJECT_REASON: ' || ? "
            "WHERE id = ?",
            (now, admin_id, reason, req_id),
        )
