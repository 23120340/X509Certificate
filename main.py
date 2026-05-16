"""
main.py
-------
Điểm vào chính của hệ thống CA Management.

    python main.py

Mở cửa sổ Login. Lần đầu chạy, hệ thống sẽ:
  • Tạo SQLite database `ca_app.db` (schema 9 bảng).
  • Tạo file `master.key` (32 bytes random, dùng cho AES-GCM).
  • Seed system_config defaults.
  • Seed tài khoản admin mặc định: admin / Admin@123 — ĐỔI ngay sau khi login.

Legacy demo "5 bước verify + lifecycle/renew" truy cập được qua
Admin Dashboard → mục "Verification Lab".
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from ui.app import main

if __name__ == "__main__":
    main()
