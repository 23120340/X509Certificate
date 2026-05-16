"""
services/system_config.py
-------------------------
Cấu hình mặc định cho việc cấp phát chứng chỉ — đáp ứng A.3.

  • Key-value store trong bảng `system_config`.
  • Seed defaults ở init_db lần đầu.
  • Admin có thể UPDATE qua UI; mỗi update ghi audit log (caller trách nhiệm).

Các key chuẩn:
  sig_algorithm           Thuật toán chữ ký (vd 'RSA-SHA256').
  hash_algorithm          Hàm băm dùng trong chữ ký (vd 'SHA256').
  default_key_size        Độ dài khóa RSA mặc định (string int, vd '2048').
  default_validity_days   Thời hạn cert mặc định (string int, vd '365').
  root_ca_validity_days   Thời hạn Root CA mặc định (string int, vd '3650').
"""

from datetime import datetime, timezone
from typing import Optional

from db.connection import conn_scope, transaction


DEFAULTS: "dict[str, str]" = {
    "sig_algorithm":         "RSA-SHA256",
    "hash_algorithm":        "SHA256",
    "default_key_size":      "2048",
    "default_validity_days": "365",
    "root_ca_validity_days": "3650",
}

# Whitelist các key user được phép set qua UI (bảo vệ khỏi typo / inject).
ALLOWED_KEYS = frozenset(DEFAULTS.keys())


def seed_defaults(db_path: str) -> int:
    """
    Insert các default chưa có. Idempotent. Trả về số key đã được insert.
    """
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    with transaction(db_path) as conn:
        for key, value in DEFAULTS.items():
            row = conn.execute(
                "SELECT 1 FROM system_config WHERE key = ?", (key,)
            ).fetchone()
            if row:
                continue
            conn.execute(
                "INSERT INTO system_config (key, value, updated_at, updated_by) "
                "VALUES (?, ?, ?, NULL)",
                (key, value, now),
            )
            inserted += 1
    return inserted


def get_config(key: str, db_path: str) -> Optional[str]:
    """Đọc 1 giá trị. Trả về None nếu key không tồn tại."""
    with conn_scope(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM system_config WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None


def get_all_config(db_path: str) -> "dict[str, str]":
    """Đọc toàn bộ config dưới dạng dict."""
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT key, value FROM system_config"
        ).fetchall()
        return {r["key"]: r["value"] for r in rows}


def set_config(key: str, value: str, updated_by: Optional[int],
               db_path: str) -> None:
    """
    Set/Update 1 config. Raise ValueError nếu key không nằm trong whitelist.
    Caller chịu trách nhiệm ghi audit log riêng (xem services/audit.py).
    """
    if key not in ALLOWED_KEYS:
        raise ValueError(
            f"Config key không hợp lệ: {key!r}. Hợp lệ: {sorted(ALLOWED_KEYS)}"
        )
    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        conn.execute(
            "INSERT INTO system_config (key, value, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET "
            "  value      = excluded.value, "
            "  updated_at = excluded.updated_at, "
            "  updated_by = excluded.updated_by",
            (key, value, now, updated_by),
        )


def get_int_config(key: str, db_path: str, fallback: int) -> int:
    """Đọc config kiểu int. Fallback nếu thiếu hoặc parse fail."""
    v = get_config(key, db_path)
    if v is None:
        return fallback
    try:
        return int(v)
    except ValueError:
        return fallback
