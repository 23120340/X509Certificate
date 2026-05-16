"""
services/auth.py
----------------
Đăng ký, đăng nhập, đổi mật khẩu cho cả Admin và Customer (cùng bảng `users`).

API trả về `dict` (subset của row), KHÔNG trả password_hash ra ngoài.
Raise `AuthError` khi nghiệp vụ sai (username trùng, sai mật khẩu, ...).
"""

from datetime import datetime, timezone
from typing import Optional

from db.connection import get_conn, transaction
from core.encryption import hash_password, verify_password


ROLES = ("admin", "customer")
MIN_PASSWORD_LEN = 6
MAX_USERNAME_LEN = 64


class AuthError(Exception):
    """Lỗi nghiệp vụ auth (sai mật khẩu, username trùng, ...)."""


# ── Validation ───────────────────────────────────────────────────────────────

def _validate_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise AuthError("Username không được rỗng.")
    if len(username) > MAX_USERNAME_LEN:
        raise AuthError(f"Username dài quá {MAX_USERNAME_LEN} ký tự.")
    # Cho phép ASCII letters/digits + một vài ký tự an toàn
    if not all(c.isalnum() or c in "._-@" for c in username):
        raise AuthError(
            "Username chỉ chấp nhận chữ/số và các ký tự . _ - @"
        )
    return username


def _validate_password(password: str) -> None:
    if not isinstance(password, str) or not password:
        raise AuthError("Password không được rỗng.")
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password phải có ít nhất {MIN_PASSWORD_LEN} ký tự.")


# ── Public API ───────────────────────────────────────────────────────────────

def register_user(username: str, password: str, role: str,
                  db_path: str) -> dict:
    """
    Đăng ký user mới. Raise AuthError nếu username trùng hoặc input không hợp lệ.
    Trả về dict {id, username, role, created_at}.
    """
    if role not in ROLES:
        raise AuthError(f"Role không hợp lệ: {role!r}. Chọn 1 trong {ROLES}.")
    username = _validate_username(username)
    _validate_password(password)

    pw_hash = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()

    with transaction(db_path) as conn:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            raise AuthError(f"Username '{username}' đã tồn tại.")
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, pw_hash, role, now),
        )
        user_id = cur.lastrowid

    return {
        "id":         user_id,
        "username":   username,
        "role":       role,
        "created_at": now,
    }


def login(username: str, password: str, db_path: str) -> dict:
    """
    Verify username + password. Trả về dict {id, username, role}.
    Raise AuthError với message generic ("sai username hoặc password") để
    không leak việc username có tồn tại hay không.
    """
    username = (username or "").strip()
    if not username or not password:
        raise AuthError("Sai username hoặc password.")

    conn = get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, password_hash, role "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        # Vẫn gọi verify_password kể cả khi row=None để tránh user-enum
        # qua timing (verify mất ~100ms).
        pw_hash = row["password_hash"] if row else (
            "scrypt$16384$8$1$" + "0" * 32 + "$" + "0" * 64
        )
        ok = verify_password(password, pw_hash)
        if not row or not ok:
            raise AuthError("Sai username hoặc password.")

        now = datetime.now(timezone.utc).isoformat()
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        conn.execute("COMMIT")

        return {
            "id":       row["id"],
            "username": row["username"],
            "role":     row["role"],
        }
    finally:
        conn.close()


def change_password(user_id: int, old_password: str, new_password: str,
                    db_path: str) -> None:
    """Đổi mật khẩu. Raise AuthError nếu sai mật khẩu cũ hoặc mật khẩu mới yếu."""
    _validate_password(new_password)
    if old_password == new_password:
        raise AuthError("Mật khẩu mới phải khác mật khẩu cũ.")

    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            raise AuthError("Không tìm thấy user.")
        if not verify_password(old_password, row["password_hash"]):
            raise AuthError("Mật khẩu cũ không đúng.")
        new_hash = hash_password(new_password)
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id),
        )


def get_user_by_id(user_id: int, db_path: str) -> Optional[dict]:
    """Trả về dict {id, username, role, created_at, last_login_at} hoặc None."""
    conn = get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, role, created_at, last_login_at "
            "FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def count_users(db_path: str, role: Optional[str] = None) -> int:
    """Đếm số user (toàn bộ, hoặc lọc theo role)."""
    conn = get_conn(db_path)
    try:
        if role:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = ?", (role,)
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return row["n"]
    finally:
        conn.close()


def seed_admin_if_empty(username: str, password: str, db_path: str
                        ) -> Optional[dict]:
    """
    Tạo admin mặc định nếu bảng users chưa có admin nào. Trả về user dict
    (mới tạo) hoặc None nếu đã có sẵn.
    """
    if count_users(db_path, role="admin") > 0:
        return None
    return register_user(username, password, "admin", db_path)
