"""
scripts/backup_db.py
--------------------
Backup utility cho hệ thống CA — đáp ứng yêu cầu nộp D.2 đồ án MHUD
("Dữ liệu của hệ thống (script, backup db)").

Cách dùng:
    python scripts/backup_db.py            # backup vào ./backups/<timestamp>/
    python scripts/backup_db.py --dest X   # backup vào X/<timestamp>/
    python scripts/backup_db.py --schema-only  # chỉ xuất schema.sql + sample data
    python scripts/backup_db.py --dump-sql     # xuất .sql dump thay vì copy file

Backup gồm:
    • ca_app.db              — file SQLite chính (toàn bộ DB)
    • master.key             — master encryption key (CỰC KÌ NHẠY CẢM)
    • certs/                 — trust store + crl.pem + ocsp_db.json
    • backup_manifest.json   — metadata + checksum
    • schema.sql             — bản sao schema để dễ inspect

LƯU Ý BẢO MẬT:
    • `master.key` mở khóa toàn bộ private key trong DB. KHÔNG commit lên
      git hay upload public bao giờ. Backup nên giữ trong USB/encrypted
      drive riêng.
    • Khi nộp đồ án (Moodle), upload thư mục backup nhưng KHÔNG kèm
      master.key nếu sợ leak; thay vào đó note rõ trong báo cáo "master.key
      bị omit để bảo mật, GV cần khôi phục từ env vars hoặc sinh mới".
"""

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB_PATH         = Path("ca_app.db")
DEFAULT_MASTER_KEY_PATH = Path("master.key")
DEFAULT_CERTS_DIR       = Path("certs")
DEFAULT_BACKUP_BASE     = Path("backups")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _table_counts(db_path: Path) -> "dict[str, int]":
    """Đếm số row mỗi bảng để verify backup integrity."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        counts = {}
        for (name,) in rows:
            n = conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            counts[name] = n
        return counts
    finally:
        conn.close()


def _dump_sql(db_path: Path, out_path: Path) -> None:
    """Dump DB sang plain SQL (CREATE TABLE + INSERT) cho dễ inspect/restore."""
    conn = sqlite3.connect(str(db_path))
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for line in conn.iterdump():
                f.write(line + "\n")
    finally:
        conn.close()


def backup(
    db_path: Path = DEFAULT_DB_PATH,
    master_key_path: Path = DEFAULT_MASTER_KEY_PATH,
    certs_dir: Path = DEFAULT_CERTS_DIR,
    dest_base: Path = DEFAULT_BACKUP_BASE,
    include_master_key: bool = True,
    dump_sql: bool = False,
) -> Path:
    """
    Tạo 1 backup snapshot. Trả về Path của thư mục backup vừa tạo.
    """
    if not db_path.exists():
        raise FileNotFoundError(f"Database không tồn tại: {db_path}")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    dest = dest_base / ts
    dest.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "backup_time_utc":  datetime.now(timezone.utc).isoformat(),
        "source_db":        str(db_path.resolve()),
        "files":            [],
        "table_counts":     {},
        "warnings":         [],
    }

    # 1. DB file
    db_out = dest / "ca_app.db"
    # Dùng SQLite backup API để snapshot consistent (kể cả khi DB đang được app write)
    src_conn = sqlite3.connect(str(db_path))
    dst_conn = sqlite3.connect(str(db_out))
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()
    manifest["files"].append({
        "name":   "ca_app.db",
        "size":   db_out.stat().st_size,
        "sha256": _sha256_file(db_out),
    })
    manifest["table_counts"] = _table_counts(db_out)

    # 2. SQL dump (optional)
    if dump_sql:
        sql_out = dest / "ca_app.sql"
        _dump_sql(db_out, sql_out)
        manifest["files"].append({
            "name":   "ca_app.sql",
            "size":   sql_out.stat().st_size,
            "sha256": _sha256_file(sql_out),
        })

    # 3. Master key
    if include_master_key and master_key_path.exists():
        mk_out = dest / "master.key"
        shutil.copy2(master_key_path, mk_out)
        manifest["files"].append({
            "name":   "master.key",
            "size":   mk_out.stat().st_size,
            "sha256": _sha256_file(mk_out),
            "warning": (
                "SENSITIVE — master.key mở khóa toàn bộ private key trong "
                "DB. KHÔNG commit hay upload public."
            ),
        })
    elif not include_master_key:
        manifest["warnings"].append(
            "master.key đã bị omit theo yêu cầu (--no-master-key). "
            "Backup không thể decrypt private keys khi restore."
        )
    else:
        manifest["warnings"].append(
            f"master.key không tồn tại tại {master_key_path} — bỏ qua."
        )

    # 4. Certs dir (trust_store + crl.pem + ocsp_db.json)
    if certs_dir.exists() and certs_dir.is_dir():
        certs_out = dest / "certs"
        shutil.copytree(certs_dir, certs_out, dirs_exist_ok=True)
        # Liệt kê các file con + sha256
        for f in certs_out.rglob("*"):
            if f.is_file():
                rel = f.relative_to(certs_out)
                manifest["files"].append({
                    "name":   f"certs/{rel.as_posix()}",
                    "size":   f.stat().st_size,
                    "sha256": _sha256_file(f),
                })
    else:
        manifest["warnings"].append(
            f"Thư mục certs {certs_dir} không tồn tại — bỏ qua."
        )

    # 5. Schema (bản sao để inspect mà không cần mở DB)
    schema_src = Path(__file__).parent.parent / "src" / "db" / "schema.sql"
    if schema_src.exists():
        schema_out = dest / "schema.sql"
        shutil.copy2(schema_src, schema_out)
        manifest["files"].append({
            "name":   "schema.sql",
            "size":   schema_out.stat().st_size,
            "sha256": _sha256_file(schema_out),
        })

    # 6. Manifest
    manifest_path = dest / "backup_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return dest


def restore_hint(backup_dir: Path) -> None:
    """In hướng dẫn restore."""
    print(
        f"""
Restore từ backup tại: {backup_dir}

  1. Đóng ứng dụng CA (nếu đang chạy).
  2. Backup state hiện tại trước khi ghi đè (an toàn):
       Move-Item ca_app.db ca_app.db.before-restore
       Move-Item master.key master.key.before-restore
       Move-Item certs certs.before-restore
  3. Copy 3 thành phần từ backup vào root project:
       Copy-Item {backup_dir}\\ca_app.db .
       Copy-Item {backup_dir}\\master.key .            # nếu có
       Copy-Item {backup_dir}\\certs . -Recurse
  4. Khởi động lại app: python main.py
  5. Verify integrity: chạy test suite hoặc kiểm tra số row khớp manifest.

LƯU Ý: master.key + ca_app.db PHẢI khớp cặp — nếu mismatch, mọi
private key trong DB sẽ không decrypt được (InvalidTag).
"""
    )


def main():
    parser = argparse.ArgumentParser(
        description="Backup utility cho hệ thống CA X.509.",
    )
    parser.add_argument(
        "--db", type=Path, default=DEFAULT_DB_PATH,
        help=f"Đường dẫn DB (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--master-key", type=Path, default=DEFAULT_MASTER_KEY_PATH,
        help=f"Đường dẫn master.key (default: {DEFAULT_MASTER_KEY_PATH}).",
    )
    parser.add_argument(
        "--certs", type=Path, default=DEFAULT_CERTS_DIR,
        help=f"Thư mục certs (default: {DEFAULT_CERTS_DIR}).",
    )
    parser.add_argument(
        "--dest", type=Path, default=DEFAULT_BACKUP_BASE,
        help=f"Thư mục cha cho backups (default: {DEFAULT_BACKUP_BASE}).",
    )
    parser.add_argument(
        "--no-master-key", action="store_true",
        help="KHÔNG copy master.key vào backup (giảm rủi ro leak).",
    )
    parser.add_argument(
        "--dump-sql", action="store_true",
        help="Xuất thêm SQL dump (ca_app.sql) ngoài file .db nhị phân.",
    )

    args = parser.parse_args()

    try:
        backup_dir = backup(
            db_path=args.db,
            master_key_path=args.master_key,
            certs_dir=args.certs,
            dest_base=args.dest,
            include_master_key=not args.no_master_key,
            dump_sql=args.dump_sql,
        )
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[backup] OK — snapshot tại: {backup_dir}")
    manifest_path = backup_dir / "backup_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"        {len(manifest['files'])} file(s) backup")
    print(f"        Table counts: {manifest['table_counts']}")
    if manifest["warnings"]:
        print("        Warnings:")
        for w in manifest["warnings"]:
            print(f"          - {w}")

    restore_hint(backup_dir)


if __name__ == "__main__":
    main()
