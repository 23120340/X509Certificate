"""
db/connection.py
----------------
SQLite connection helper.

  • `init_db(path)` áp dụng schema.sql (idempotent — `CREATE TABLE IF NOT EXISTS`).
  • `get_conn(path)` mở connection với:
      - foreign_keys = ON (SQLite mặc định TẮT)
      - row_factory = Row (truy cập cột bằng tên)
      - isolation_level = None (autocommit OFF — bạn quản lý transaction tay
        bằng BEGIN/COMMIT, hoặc dùng context manager `transaction()`)
  • `transaction(path)` là context manager: tự BEGIN, COMMIT khi thoát bình
    thường, ROLLBACK khi raise.

Lưu ý về isolation_level:
  Khi `isolation_level=None`, sqlite3 KHÔNG tự mở implicit transaction trước
  DML — kết nối chạy ở chế độ autocommit. Muốn nhóm nhiều câu lệnh trong 1
  transaction, gọi BEGIN tay (qua `transaction()` context manager).
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = "ca_app.db"
SCHEMA_PATH     = Path(__file__).parent / "schema.sql"


def get_conn(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Mở SQLite connection ở chế độ autocommit + foreign_keys ON."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL mode — tốt cho desktop app với reader đồng thời (UI + background work).
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Tạo schema. Idempotent (CREATE TABLE IF NOT EXISTS)."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn = get_conn(db_path)
    try:
        conn.executescript(schema)
    finally:
        conn.close()


@contextmanager
def transaction(db_path: str = DEFAULT_DB_PATH):
    """
    Context manager mở 1 transaction (autocommit OFF tạm thời).

        with transaction(db_path) as conn:
            conn.execute(...)
            conn.execute(...)
        # COMMIT tự chạy khi thoát without exception, ROLLBACK nếu raise.
    """
    conn = get_conn(db_path)
    try:
        conn.execute("BEGIN")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
    finally:
        conn.close()


@contextmanager
def conn_scope(db_path: str = DEFAULT_DB_PATH):
    """Context manager cho read-only — chỉ mở/đóng conn, không bao BEGIN/COMMIT."""
    conn = get_conn(db_path)
    try:
        yield conn
    finally:
        conn.close()
