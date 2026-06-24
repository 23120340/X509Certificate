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

from core import keyalg
from core.csr import build_csr, csr_to_pem, parse_csr
from services.customer_keys import load_private_key, get_key_meta, CustomerKeyError
from db.connection import conn_scope, transaction


VALID_STATUS = ("pending", "approved", "rejected")
MAX_CANCEL_REASON_LEN = 500


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
    if meta.get("compromised_at"):
        raise CSRError(
            "Keypair này đã bị đánh dấu LỘ KHÓA — không thể dùng để xin chứng "
            "chỉ nữa. Hãy sinh keypair mới."
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


def domains_for_key(
    customer_key_id: int, requester_id: int, db_path: str,
) -> "list[str]":
    """
    Distinct common_name của các CSR (pending/approved) đã dùng keypair này
    bởi chính `requester_id`. Dùng để CẢNH BÁO khi một key sắp được dùng cho
    domain thứ hai — reuse khóa làm phình blast-radius nếu private key bị lộ
    (mọi domain chung key phải thu hồi cùng lúc, xem revoke_certs_by_key).

    Chỉ tính CSR của owner (BOLA guard qua requester_id). KHÔNG tính CSR đã
    rejected/cancelled (không sinh ra cert nên không làm tăng rủi ro).
    """
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT common_name FROM csr_requests "
            "WHERE customer_key_id = ? AND requester_id = ? "
            "  AND status IN ('pending', 'approved') "
            "ORDER BY common_name",
            (customer_key_id, requester_id),
        ).fetchall()
    return [r["common_name"] for r in rows]


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


# ── Hủy CSR pending khi khóa bị thu hồi / lộ (containment) ────────────────────
#
# Khi một keypair bị vô hiệu hóa (Admin revoke-by-key, hoặc duyệt yêu cầu thu hồi
# có cờ lộ khóa), mọi cert dùng khóa đó bị thu hồi VÀ keypair bị wipe. Nhưng CSR
# đang 'pending' dùng chính khóa đó vẫn còn — nếu admin lỡ duyệt thì lại phát hành
# cert mới TỪ MỘT KHÓA ĐÃ LỘ. PKI thực luôn loại bỏ yêu cầu cấp chứng chỉ trên
# khóa đã thu hồi/lộ, nên ta hủy luôn các CSR pending đó cho khớp logic hạ tầng.
#
# Định danh khóa = SHA-256(SubjectPublicKeyInfo) trích trực tiếp từ public key
# trong CSR PEM — CÙNG nguồn sự thật với cert_lifecycle/customer_keys, nên gom
# đúng cả CSR LAN (chỉ có public key) lẫn CSR nội bộ.

def _csr_pem_fingerprint(csr_pem) -> "str | None":
    """Fingerprint khóa (SHA-256 SPKI) từ CSR PEM (bytes/str). None nếu PEM hỏng
    (skip phòng thủ — không vì 1 CSR lỗi mà chặn cả batch)."""
    try:
        csr = parse_csr(bytes(csr_pem))
    except Exception:
        return None
    return keyalg.public_key_fingerprint(csr.public_key())


def cancel_pending_csrs_for_fingerprint(
    fingerprint: str,
    db_path: str,
    admin_id: Optional[int] = None,
    owner_id: Optional[int] = None,
    reason: str = "Tự hủy: keypair đã bị thu hồi/đánh dấu lộ khóa.",
) -> "list[int]":
    """
    Hủy MỌI CSR đang 'pending' có public key khớp `fingerprint` (đặt status
    'rejected', ghi `reject_reason`). Dùng làm bước containment sau revoke-by-key
    / duyệt thu hồi lộ khóa: khóa đã vô hiệu hóa không được phép sinh thêm cert.

    owner_id != None → chỉ trong phạm vi chủ sở hữu đó (cascade do customer yêu
    cầu — giữ kỷ luật BOLA). owner_id None → mọi chủ sở hữu (công cụ revoke-by-key
    phía Admin, có thẩm quyền containment liên-chủ-sở-hữu).
    `admin_id` (nếu có) được ghi vào reviewed_by để truy vết.

    Idempotent: CSR đã không còn 'pending' được bỏ qua (guard rowcount).
    Trả về list id các CSR vừa bị hủy.
    """
    reason = (reason or "").strip()[:MAX_CANCEL_REASON_LEN] or "key compromised"
    now = datetime.now(timezone.utc).isoformat()
    cancelled: "list[int]" = []
    with transaction(db_path) as conn:
        rows = conn.execute(
            "SELECT id, requester_id, csr_pem FROM csr_requests "
            "WHERE status = 'pending'"
        ).fetchall()
        for r in rows:
            if owner_id is not None and r["requester_id"] != owner_id:
                continue   # giới hạn phạm vi chủ sở hữu (rẻ hơn parse PEM → check trước)
            if _csr_pem_fingerprint(r["csr_pem"]) != fingerprint:
                continue
            cur = conn.execute(
                "UPDATE csr_requests SET status = 'rejected', "
                "    reject_reason = ?, reviewed_at = ?, reviewed_by = ? "
                "WHERE id = ? AND status = 'pending'",
                (reason, now, admin_id, r["id"]),
            )
            if cur.rowcount > 0:
                cancelled.append(r["id"])
    return cancelled
