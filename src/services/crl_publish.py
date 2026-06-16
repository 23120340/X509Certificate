"""
services/crl_publish.py
-----------------------
Snapshot revocation state từ DB → ký CRL bằng Root CA active → ghi file.
Đáp ứng A.10 "Cập nhật danh sách thu hồi chứng nhận".

  • snapshot_revoked_serials(db_path) → list[int]
        Tất cả serial (int) của cert có revoked_at != NULL.
  • publish_crl(admin_id, db_path, crl_path, ocsp_db_path, validity_days)
        Build + ký CRL, ghi `crl_path` (cho infra/crl_server) và đồng bộ
        `ocsp_db_path` (cho infra/ocsp_server, format JSON list[int-as-str]).
        Trả về dict {revoked_count, crl_path, ocsp_db_path, this_update,
                     next_update}.
  • get_published_crl_info(crl_path) → dict | None
        Đọc file CRL hiện tại, trả về metadata (issuer, this_update,
        next_update, count) để hiển thị trên UI.

Tham số `validity_days` mặc định lấy từ `system_config.crl_validity_days`
nếu có (chưa whitelist trong M4 — caller pass thẳng).
"""

import os
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509

from core.crl import build_crl, save_crl, save_revoked_list
from db.connection import conn_scope
from services.ca_admin import load_active_root_ca_with_key, CAError
from services.system_config import get_hash_algorithm
from config import PROD_CRL_PATH, PROD_OCSP_DB_PATH


# Alias giữ tên cũ để các file dùng import này không phải đổi.
DEFAULT_CRL_PATH      = PROD_CRL_PATH
DEFAULT_OCSP_DB_PATH  = PROD_OCSP_DB_PATH
DEFAULT_CRL_VALIDITY  = 7  # ngày


class CRLPublishError(Exception):
    pass


# ── Snapshot from DB ─────────────────────────────────────────────────────────

def snapshot_revoked_serials(db_path: str) -> "list[int]":
    """
    Đọc tất cả issued_certs có revoked_at != NULL, parse serial_hex → int.
    KHÔNG loại trừ cert đã hết hạn — CRL chuẩn vẫn list các cert revoked
    cho tới khi quá Not After một thời gian (CA tự định).
    """
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT serial_hex FROM issued_certs "
            "WHERE revoked_at IS NOT NULL ORDER BY revoked_at ASC"
        ).fetchall()
    out: list[int] = []
    for r in rows:
        try:
            out.append(int(r["serial_hex"], 16))
        except (ValueError, TypeError):
            # serial_hex lưu trong DB không hợp lệ — skip + warn
            import sys
            print(
                f"[crl_publish] WARN: serial_hex không parse được: "
                f"{r['serial_hex']!r}", file=sys.stderr,
            )
    return out


def snapshot_revoked(db_path: str) -> "list[tuple[int, str]]":
    """
    Như snapshot_revoked_serials nhưng KÈM revoked_at (ISO) của từng cert, để
    CRL ghi đúng NGÀY THU HỒI THỰC của mỗi serial (thay vì gán đồng loạt thời
    điểm publish). Trả về list[(serial_int, revoked_at_iso)].
    """
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT serial_hex, revoked_at FROM issued_certs "
            "WHERE revoked_at IS NOT NULL ORDER BY revoked_at ASC"
        ).fetchall()
    out: "list[tuple[int, str]]" = []
    for r in rows:
        try:
            out.append((int(r["serial_hex"], 16), r["revoked_at"]))
        except (ValueError, TypeError):
            import sys
            print(
                f"[crl_publish] WARN: serial_hex không parse được: "
                f"{r['serial_hex']!r}", file=sys.stderr,
            )
    return out


# ── Publish ──────────────────────────────────────────────────────────────────

def sync_ocsp_db(
    db_path: str,
    ocsp_db_path: Optional[str] = DEFAULT_OCSP_DB_PATH,
) -> "dict | None":
    """
    Sync the OCSP responder JSON from the current DB revocation snapshot.

    This does not require Root CA signing, so revoke flows can call it
    immediately while CRL publication remains a separate manual snapshot.
    """
    if not ocsp_db_path:
        return None
    serials = snapshot_revoked_serials(db_path)
    os.makedirs(os.path.dirname(ocsp_db_path) or ".", exist_ok=True)
    save_revoked_list(serials, ocsp_db_path)
    return {
        "revoked_count": len(serials),
        "ocsp_db_path": os.path.abspath(ocsp_db_path),
    }


def publish_crl(
    admin_id: int,
    db_path: str,
    crl_path: str = DEFAULT_CRL_PATH,
    ocsp_db_path: Optional[str] = DEFAULT_OCSP_DB_PATH,
    validity_days: int = DEFAULT_CRL_VALIDITY,
) -> dict:
    """
    Build CRL từ snapshot DB, ký bằng Root CA active, ghi `crl_path`.
    Nếu `ocsp_db_path` != None thì đồng bộ JSON cho OCSP responder.

    Raise CRLPublishError nếu chưa có Root CA active.
    Trả về dict metadata.
    """
    try:
        ca_cert, ca_key = load_active_root_ca_with_key(db_path)
    except CAError as e:
        raise CRLPublishError(
            f"Không publish được CRL: {e} Tạo Root CA trước."
        ) from e

    # Lấy serial KÈM ngày thu hồi thực để mỗi entry CRL giữ đúng mốc của nó.
    pairs = snapshot_revoked(db_path)
    serials = [s for s, _ in pairs]
    revocation_dates: "dict[int, datetime]" = {}
    for s, rdate in pairs:
        try:
            dt = datetime.fromisoformat(rdate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            revocation_dates[s] = dt
        except (ValueError, TypeError):
            pass  # thiếu/format lạ → build_crl fallback dùng now cho serial đó

    crl = build_crl(ca_cert, ca_key, serials, validity_days=validity_days,
                    hash_algorithm=get_hash_algorithm(db_path),
                    revocation_dates=revocation_dates)

    os.makedirs(os.path.dirname(crl_path) or ".", exist_ok=True)
    save_crl(crl, crl_path)

    if ocsp_db_path:
        sync_ocsp_db(db_path, ocsp_db_path)

    try:
        this_update = crl.last_update_utc.isoformat()
        next_update = crl.next_update_utc.isoformat()
    except AttributeError:
        this_update = crl.last_update.isoformat()
        next_update = crl.next_update.isoformat()

    return {
        "revoked_count": len(serials),
        "crl_path":      os.path.abspath(crl_path),
        "ocsp_db_path":  os.path.abspath(ocsp_db_path) if ocsp_db_path else None,
        "this_update":   this_update,
        "next_update":   next_update,
        "issuer":        ca_cert.subject.rfc4514_string(),
    }


# ── Read current CRL ─────────────────────────────────────────────────────────

def list_crl_entries(
    crl_path: str = DEFAULT_CRL_PATH,
    db_path: Optional[str] = None,
) -> "list[dict]":
    """
    Parse file CRL, trả về list các entry revoked. Nếu truyền `db_path` thì
    enrich thêm `common_name`/`owner_username` bằng cách JOIN serial_hex
    với bảng issued_certs (cho UX dễ đọc hơn — không bắt buộc).

    Trả về list rỗng nếu file không tồn tại / không parse được.
    """
    if not os.path.exists(crl_path):
        return []
    try:
        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except Exception:
        return []

    entries: "list[dict]" = []
    for rev in crl:
        try:
            rd = rev.revocation_date_utc
        except AttributeError:
            rd = rev.revocation_date
        entries.append({
            "serial_hex":      f"{rev.serial_number:x}",
            "serial_int":      rev.serial_number,
            "revocation_date": rd.isoformat() if hasattr(rd, "isoformat") else str(rd),
            "common_name":     "",
            "owner_username":  "",
        })

    if db_path:
        from db.connection import conn_scope
        with conn_scope(db_path) as conn:
            for e in entries:
                row = conn.execute(
                    "SELECT ic.common_name, u.username AS owner_username "
                    "FROM issued_certs ic "
                    "LEFT JOIN users u ON u.id = ic.owner_id "
                    "WHERE ic.serial_hex = ?",
                    (e["serial_hex"],),
                ).fetchone()
                if row:
                    e["common_name"] = row["common_name"] or ""
                    e["owner_username"] = row["owner_username"] or ""

    return entries


def get_published_crl_info(crl_path: str = DEFAULT_CRL_PATH
                            ) -> Optional[dict]:
    """
    Đọc file CRL hiện có để hiển thị info. Trả về None nếu file không tồn
    tại hoặc không parse được.
    """
    if not os.path.exists(crl_path):
        return None
    try:
        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except Exception:
        return None
    try:
        this_update = crl.last_update_utc.isoformat()
        next_update = crl.next_update_utc.isoformat()
    except AttributeError:
        this_update = crl.last_update.isoformat()
        next_update = crl.next_update.isoformat()
    count = sum(1 for _ in crl)
    return {
        "crl_path":     os.path.abspath(crl_path),
        "issuer":       crl.issuer.rfc4514_string(),
        "this_update":  this_update,
        "next_update":  next_update,
        "revoked_count": count,
        "file_size":    os.path.getsize(crl_path),
    }
