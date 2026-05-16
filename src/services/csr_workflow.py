"""
services/csr_workflow.py
------------------------
CSR submission + lifecycle — đáp ứng B.5, B.6 (customer side), A.6-7 (admin side).

Trong M5 chỉ làm phần customer:
  • submit_csr(...)            — customer tạo CSR + lưu vào DB (status=pending)
  • list_my_csr(...)           — xem CSR của chính mình
  • get_my_csr_by_id(...)      — chi tiết 1 CSR (kiểm tra ownership)
  • cancel_csr(...)            — hủy CSR pending (chưa duyệt)

Phần admin (approve/reject + issue cert) làm trong M6 (`csr_admin.py`).

Tham chiếu module:
  • core/csr.py        — build/parse/verify CSR PKCS#10
  • customer_keys.py   — load private key của user để ký CSR
"""

import json
from datetime import datetime, timezone
from typing import Optional

from core.csr import build_csr, csr_to_pem
from services.customer_keys import load_private_key, get_key_meta, CustomerKeyError
from db.connection import conn_scope, transaction


VALID_STATUS = ("pending", "approved", "rejected")


class CSRError(Exception):
    """Lỗi nghiệp vụ trong CSR workflow."""


def _validate_common_name(cn: str) -> str:
    cn = (cn or "").strip()
    if not cn:
        raise CSRError("Common Name (tên miền) không được rỗng.")
    if len(cn) > 253:
        raise CSRError("Common Name dài quá 253 ký tự.")
    # Cho phép wildcard '*' ở đầu, vd "*.example.com"
    name_to_check = cn[2:] if cn.startswith("*.") else cn
    if not all(c.isalnum() or c in ".-" for c in name_to_check):
        raise CSRError(
            "Common Name chỉ chấp nhận chữ/số/dấu '.' '-' (và '*.' ở đầu cho wildcard)."
        )
    return cn


def _normalize_san_list(san: "list[str] | None") -> "list[str]":
    if not san:
        return []
    out: "list[str]" = []
    seen = set()
    for s in san:
        s = (s or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# ── Public API ───────────────────────────────────────────────────────────────

def submit_csr(
    requester_id: int,
    customer_key_id: int,
    common_name: str,
    san_list: "list[str] | None",
    db_path: str,
) -> dict:
    """
    Tạo CSR cho domain `common_name` (+ SAN), ký bằng private key của
    keypair `customer_key_id`. Lưu PEM CSR vào DB với status=pending.

    Đảm bảo `customer_key_id` thuộc về `requester_id` (BOLA guard).
    Trả về dict {id, common_name, status, submitted_at, customer_key_id}.
    """
    common_name = _validate_common_name(common_name)
    san_list = _normalize_san_list(san_list)

    # Verify ownership của key
    meta = get_key_meta(customer_key_id, requester_id, db_path)
    if meta is None:
        raise CSRError(
            f"Keypair id={customer_key_id} không thuộc về bạn (hoặc không tồn tại)."
        )

    # Decrypt key + tạo CSR
    try:
        key = load_private_key(customer_key_id, requester_id, db_path)
    except CustomerKeyError as e:
        raise CSRError(str(e)) from e

    csr = build_csr(key, common_name=common_name, san_list=san_list)
    csr_pem = csr_to_pem(csr)

    submitted_at = datetime.now(timezone.utc).isoformat()
    san_json = json.dumps(san_list, ensure_ascii=False) if san_list else None

    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO csr_requests "
            "(requester_id, customer_key_id, common_name, san_list_json, "
            " csr_pem, status, submitted_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (requester_id, customer_key_id, common_name, san_json,
             csr_pem, submitted_at),
        )
        csr_id = cur.lastrowid

    return {
        "id":              csr_id,
        "common_name":     common_name,
        "san_list":        san_list,
        "status":          "pending",
        "submitted_at":    submitted_at,
        "customer_key_id": customer_key_id,
    }


def list_my_csr(
    requester_id: int,
    db_path: str,
    status: Optional[str] = None,
) -> "list[dict]":
    """Danh sách CSR của user, newest first. Filter theo status nếu có."""
    if status is not None and status not in VALID_STATUS:
        raise CSRError(f"Status không hợp lệ: {status}")

    where = ["requester_id = ?"]
    params: list = [requester_id]
    if status:
        where.append("status = ?"); params.append(status)

    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT id, customer_key_id, common_name, san_list_json, status, "
            "       reject_reason, submitted_at, reviewed_at "
            "FROM csr_requests WHERE " + " AND ".join(where) +
            " ORDER BY id DESC",
            params,
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            d = dict(r)
            d["san_list"] = (
                json.loads(d.pop("san_list_json")) if d.get("san_list_json") else []
            )
            out.append(d)
        return out


def get_my_csr_by_id(csr_id: int, requester_id: int, db_path: str) -> Optional[dict]:
    """Chi tiết 1 CSR (kèm csr_pem) — verify ownership."""
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT id, requester_id, customer_key_id, common_name, "
            "       san_list_json, csr_pem, status, reject_reason, "
            "       submitted_at, reviewed_at, reviewed_by "
            "FROM csr_requests WHERE id = ? AND requester_id = ?",
            (csr_id, requester_id),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["san_list"] = (
            json.loads(d.pop("san_list_json")) if d.get("san_list_json") else []
        )
        return d


def cancel_csr(csr_id: int, requester_id: int, db_path: str) -> None:
    """
    User hủy CSR của chính mình. Chỉ áp dụng status=pending.
    Đánh dấu rejected với reason="cancelled by requester" để giữ history.
    """
    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM csr_requests "
            "WHERE id = ? AND requester_id = ?",
            (csr_id, requester_id),
        ).fetchone()
        if row is None:
            raise CSRError("Không tìm thấy CSR này.")
        if row["status"] != "pending":
            raise CSRError(
                f"CSR đang ở trạng thái '{row['status']}', không thể hủy."
            )
        conn.execute(
            "UPDATE csr_requests SET status = 'rejected', "
            "    reject_reason = 'cancelled by requester', "
            "    reviewed_at = ?, reviewed_by = ? "
            "WHERE id = ?",
            (now, requester_id, csr_id),
        )
