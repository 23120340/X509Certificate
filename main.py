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

Lưu ý: app dùng relative path cho `master.key`, `ca_app.db`, `certs/`,
`received_certs/`. Để các file này luôn nằm cạnh `main.py` bất kể bạn chạy
từ thư mục nào, ta `os.chdir(project_root)` ngay đây.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# Anchor cwd về project root → mọi relative path trong app (master.key,
# ca_app.db, certs/, received_certs/, backups/, certs/trust_store/) đều
# resolve về đây thay vì cwd nơi user chạy command.
os.chdir(PROJECT_ROOT)

sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ui.app import main

if __name__ == "__main__":
    main()
