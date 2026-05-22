"""
scripts/dump_cert.py
--------------------
Export 1 cert từ DB ra file PEM để test Upload + Verify (B.9).

Usage:
    python scripts/dump_cert.py                    # list all certs
    python scripts/dump_cert.py <cert_id>          # dump ra ./dumped_cert_<id>.pem
    python scripts/dump_cert.py <cert_id> <path>   # dump vào path tùy ý

Tiện cho demo: thay vì phải qua UI Customer → My Certs → Save As, chỉ cần
chạy 1 dòng để có file PEM upload thử.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

import sqlite3
from config import DB_FILE


def list_certs(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT c.id, c.common_name, c.serial_hex, c.not_valid_after, "
            "       c.revoked_at, u.username "
            "FROM issued_certs c "
            "LEFT JOIN users u ON u.id = c.owner_id "
            "ORDER BY c.id DESC"
        ).fetchall()

    if not rows:
        print("Chua co cert nao trong DB.")
        print("Quy trinh: Admin tao Root CA + duyet CSR → cert se xuat hien.")
        return

    print(f"{'ID':>4} {'Owner':<12} {'CN':<24} {'Serial':<24} "
          f"{'Status':<8} {'Expires':<20}")
    print("-" * 100)
    for r in rows:
        status = "REVOKED" if r["revoked_at"] else "active"
        serial_short = r["serial_hex"][:20] + "..."
        print(
            f"{r['id']:>4} {r['username'] or '?':<12} "
            f"{r['common_name']:<24} {serial_short:<24} "
            f"{status:<8} {r['not_valid_after'][:19]}"
        )
    print()
    print(f"Dump 1 cert: python scripts/dump_cert.py <id>")


def dump_cert(db_path: str, cert_id: int, out_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT cert_pem, common_name, serial_hex "
            "FROM issued_certs WHERE id = ?",
            (cert_id,),
        ).fetchone()
    if row is None:
        print(f"[FAIL] Khong tim thay cert id={cert_id}")
        sys.exit(1)

    pem, cn, serial = row
    Path(out_path).write_bytes(pem if isinstance(pem, bytes) else pem.encode())
    print(f"[OK] Da dump cert #{cert_id} ({cn}, serial {serial[:16]}...) → {out_path}")
    print()
    print("Test trong app:")
    print(f"  Customer → Upload cert ngoai → chon file: {out_path}")
    print(f"  → Verify → hostname: {cn}")


def main():
    db_path = str(_ROOT / DB_FILE)
    if not Path(db_path).exists():
        print(f"[FAIL] DB chua ton tai: {db_path}")
        print("Chay 'python main.py' lan dau de init DB.")
        sys.exit(1)

    if len(sys.argv) == 1:
        list_certs(db_path)
        return

    try:
        cert_id = int(sys.argv[1])
    except ValueError:
        print(f"[FAIL] cert_id phai la so nguyen, got '{sys.argv[1]}'")
        sys.exit(1)

    out_path = (
        sys.argv[2] if len(sys.argv) >= 3
        else f"dumped_cert_{cert_id}.pem"
    )
    dump_cert(db_path, cert_id, out_path)


if __name__ == "__main__":
    main()
