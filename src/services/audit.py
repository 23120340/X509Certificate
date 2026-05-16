"""
services/audit.py
-----------------
Audit log — đáp ứng A.11 "Theo dõi nhật ký quá trình hoạt động chính của hệ thống".

Mỗi event là 1 row trong bảng `audit_log`:
  • actor_id      — ai gây event (NULL nếu hệ thống)
  • action        — tên ngắn snake_case ('login', 'csr_submit', 'cert_revoke', ...)
  • target_type   — loại object bị tác động (vd 'csr', 'cert', 'user')
  • target_id     — string id (giữ TEXT để chấp nhận serial hex, uuid, ...)
  • details_json  — JSON các thông tin phụ (lý do, before/after, ...)
  • timestamp     — UTC ISO-8601

Module này KHÔNG raise — log audit không được phá vỡ business flow. Lỗi
ghi log thì im lặng nuốt (write tốt-nhất-có-thể). Caller không cần wrap.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from db.connection import get_conn, conn_scope


# Catalog action keys — định nghĩa tập trung để tránh typo rải rác codebase.
# Thêm vào đây khi có flow mới.
class Action:
    # Auth
    LOGIN              = "login"
    LOGIN_FAILED       = "login_failed"
    LOGOUT             = "logout"
    REGISTER           = "register"
    PASSWORD_CHANGED   = "password_changed"

    # System config
    CONFIG_UPDATED     = "config_updated"

    # Root CA
    ROOT_CA_CREATED    = "root_ca_created"
    ROOT_CA_ROTATED    = "root_ca_rotated"

    # Customer keys
    KEY_GENERATED      = "key_generated"

    # CSR workflow
    CSR_SUBMITTED      = "csr_submitted"
    CSR_APPROVED       = "csr_approved"
    CSR_REJECTED       = "csr_rejected"

    # Cert lifecycle
    CERT_ISSUED        = "cert_issued"
    CERT_RENEWED       = "cert_renewed"
    CERT_REVOKED       = "cert_revoked"

    # Revocation workflow
    REVOKE_REQUESTED   = "revoke_requested"
    REVOKE_APPROVED    = "revoke_approved"
    REVOKE_REJECTED    = "revoke_rejected"

    # CRL
    CRL_PUBLISHED      = "crl_published"

    # External cert
    EXTERNAL_UPLOADED  = "external_cert_uploaded"


def write_audit(
    db_path: str,
    actor_id: Optional[int],
    action: str,
    *,
    target_type: Optional[str] = None,
    target_id:   Optional[str] = None,
    details:     Optional[dict] = None,
) -> None:
    """
    Ghi 1 audit event. Best-effort: lỗi DB sẽ KHÔNG raise, chỉ in lên stderr.
    Caller không cần try/except quanh hàm này.
    """
    now = datetime.now(timezone.utc).isoformat()
    details_json = (
        json.dumps(details, ensure_ascii=False, default=str)
        if details else None
    )
    try:
        conn = get_conn(db_path)
        try:
            conn.execute("BEGIN")
            conn.execute(
                "INSERT INTO audit_log "
                "(actor_id, action, target_type, target_id, details_json, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (actor_id, action, target_type, target_id, details_json, now),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
    except Exception as e:
        # Log audit KHÔNG bao giờ phá business flow. In stderr để dev biết.
        import sys
        print(f"[audit] FAILED to write event '{action}': {e}", file=sys.stderr)


def list_recent(db_path: str, limit: int = 100,
                actor_id: Optional[int] = None,
                action:   Optional[str] = None) -> list[dict]:
    """
    Trả về list event mới nhất (DESC theo id). Tham số `actor_id`/`action`
    để filter (None = không filter).
    """
    where, params = [], []
    if actor_id is not None:
        where.append("actor_id = ?"); params.append(actor_id)
    if action is not None:
        where.append("action = ?");   params.append(action)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT id, actor_id, action, target_type, target_id, "
            "details_json, timestamp FROM audit_log"
            + where_sql + " ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [dict(r) for r in rows]
