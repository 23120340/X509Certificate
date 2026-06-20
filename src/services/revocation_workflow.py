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
from services.cert_lifecycle import (
    certs_sharing_public_key, key_fingerprint_for_cert, CertLifecycleError,
)
from services.customer_keys import compromise_keys_for_fingerprint
from services.crl_publish import (
    DEFAULT_OCSP_DB_PATH,
    sync_ocsp_db,
    publish_crl,
    CRLPublishError,
)


MAX_REASON_LEN = 500
VALID_STATUS = ("pending", "approved", "rejected")


class RevocationWorkflowError(Exception):
    pass


# ── Submit (customer side) ───────────────────────────────────────────────────

def submit_revoke_request(
    cert_id: int, requester_id: int, reason: str, db_path: str,
    key_compromise: bool = False,
) -> dict:
    """
    Customer gửi yêu cầu thu hồi cert của mình. Validate:
      • cert tồn tại + thuộc requester_id (BOLA guard)
      • cert chưa revoked
      • cert chưa có request pending nào khác
      • reason không rỗng (max MAX_REASON_LEN ký tự)

    `key_compromise=True` đánh dấu "nghi ngờ lộ private key" → khi admin approve,
    thu hồi TẤT CẢ cert dùng chung khóa (cascade), không chỉ cert này.
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
            "(issued_cert_id, requester_id, reason, key_compromise, "
            " status, submitted_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (cert_id, requester_id, reason, 1 if key_compromise else 0, now),
        )
        req_id = cur.lastrowid

    return {
        "id":             req_id,
        "issued_cert_id": cert_id,
        "requester_id":   requester_id,
        "reason":         reason,
        "key_compromise": bool(key_compromise),
        "status":         "pending",
        "submitted_at":   now,
    }


# ── Queries ──────────────────────────────────────────────────────────────────

def _join_query(where: str, params: tuple) -> str:
    """SQL chung kèm JOIN ra cert + user info."""
    sql = (
        "SELECT r.id, r.issued_cert_id, r.requester_id, "
        "       u.username AS requester_username, "
        "       r.reason, r.key_compromise, r.status, r.submitted_at, "
        "       r.reviewed_at, r.reviewed_by, "
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
    ocsp_db_path: "str | None" = DEFAULT_OCSP_DB_PATH,
    crl_path: "str | None" = None,
) -> dict:
    """
    Approve revocation request atomic:
      • UPDATE revocation_requests.status = 'approved'
      • Thu hồi cert. Nếu request KHÔNG đánh dấu key_compromise → chỉ thu hồi
        đúng cert được yêu cầu (như cũ). Nếu CÓ key_compromise → CASCADE: thu
        hồi MỌI cert chưa-thu-hồi dùng chung public key với cert đó
        (containment khi lộ khóa, xem cert_lifecycle.certs_sharing_public_key).
      • Cert nào đã revoked từ trước thì giữ nguyên revoked_at cũ.

    Mọi UPDATE nằm trong 1 transaction; sau đó sync OCSP 1 lần + (tùy chọn)
    publish CRL.

    Raise RevocationWorkflowError nếu:
      • Request không tồn tại
      • Request không ở status pending
    """
    now = datetime.now(timezone.utc).isoformat()

    # Peek (read-only) để biết cert + cờ key_compromise + chủ sở hữu, từ đó tính
    # tập cert cần thu hồi TRƯỚC khi mở transaction (scan siblings là read-only).
    with conn_scope(db_path) as conn:
        peek = conn.execute(
            "SELECT r.issued_cert_id, r.key_compromise, r.status, "
            "       ic.owner_id AS cert_owner_id "
            "FROM revocation_requests r "
            "LEFT JOIN issued_certs ic ON ic.id = r.issued_cert_id "
            "WHERE r.id = ?", (req_id,),
        ).fetchone()
    if peek is None:
        raise RevocationWorkflowError("Không tìm thấy request.")
    if peek["status"] != "pending":
        raise RevocationWorkflowError(
            f"Request đang ở status '{peek['status']}', không approve được."
        )
    cert_id = peek["issued_cert_id"]
    key_compromise = bool(peek["key_compromise"])

    if key_compromise:
        # CHỈ cascade trong phạm vi cert của CHÍNH chủ sở hữu request (BOLA):
        # yêu cầu của customer không được tác động cert của người khác — kể cả
        # khi (cực hiếm) trùng public key. Admin muốn cascade liên-chủ-sở-hữu thì
        # dùng công cụ revoke-by-key phía Admin (cert_lifecycle.revoke_certs_by_key).
        try:
            siblings = certs_sharing_public_key(
                cert_id, db_path, owner_id=peek["cert_owner_id"],
            )
            target_ids = [s["id"] for s in siblings if s["status"] != "revoked"]
        except CertLifecycleError:
            target_ids = [cert_id]   # fallback an toàn: ít nhất thu hồi cert gốc
        if cert_id not in target_ids:
            # cert gốc có thể đã revoked sẵn — vẫn thử (UPDATE có guard rowcount)
            target_ids.append(cert_id)
    else:
        target_ids = [cert_id]

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
            (cert_id,),
        ).fetchone()
        if cert is None:
            raise RevocationWorkflowError(
                "Cert không tồn tại nữa — không thể approve."
            )

        # Cascade lộ khóa: đánh dấu rõ trong revocation_reason để audit phân biệt
        # cert bị thu hồi trực tiếp vs bị gom theo khóa (cap MAX_REASON_LEN).
        if key_compromise:
            # Cắt phần reason gốc TRƯỚC khi gắn marker để marker không bị mất
            # khi reason đã dài sát MAX_REASON_LEN.
            marker = f" [key-compromise cascade — request #{req_id}]"
            base = req["reason"][: max(0, MAX_REASON_LEN - len(marker))]
            revoke_reason = (base + marker)[:MAX_REASON_LEN]
        else:
            revoke_reason = req["reason"]

        revoked_ids: "list[int]" = []
        for cid in target_ids:
            cur = conn.execute(
                "UPDATE issued_certs SET revoked_at = ?, revocation_reason = ? "
                "WHERE id = ? AND revoked_at IS NULL",
                (now, revoke_reason, cid),
            )
            if cur.rowcount > 0:
                revoked_ids.append(cid)

        # Set request approved
        conn.execute(
            "UPDATE revocation_requests SET status = 'approved', "
            "    reviewed_at = ?, reviewed_by = ? WHERE id = ?",
            (now, admin_id, req_id),
        )

    cert_was_revoked = cert_id in revoked_ids

    sync_ocsp_db(db_path, ocsp_db_path)

    # Lộ khóa → đánh dấu + wipe private key (chỉ trong phạm vi chủ sở hữu request).
    compromised_key_ids: "list[int]" = []
    if key_compromise:
        try:
            fp = key_fingerprint_for_cert(cert_id, db_path)
            compromised_key_ids = compromise_keys_for_fingerprint(
                fp, db_path, owner_id=peek["cert_owner_id"],
            )
        except CertLifecycleError:
            compromised_key_ids = []

    crl_result = None
    crl_error = None
    if crl_path:
        try:
            crl_result = publish_crl(
                admin_id=admin_id,
                db_path=db_path,
                crl_path=crl_path,
                ocsp_db_path=ocsp_db_path,
            )
        except CRLPublishError as e:
            crl_error = str(e)
    return {
        "id":               req_id,
        "issued_cert_id":   cert_id,
        "reviewed_at":      now,
        "reviewed_by":      admin_id,
        "key_compromise":   key_compromise,
        "cert_was_revoked": cert_was_revoked,
        "cert_revoked_at":  now if cert_was_revoked else cert["revoked_at"],
        "revoked_ids":      revoked_ids,
        "revoked_count":    len(revoked_ids),
        "compromised_key_ids": compromised_key_ids,
        "crl_result":       crl_result,
        "crl_error":        crl_error,
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
