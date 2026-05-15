"""
main.py
-------
Điểm vào của chương trình. Chỉ việc chạy:

    python main.py

Sẽ mở cửa sổ GUI.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from gui import main

if __name__ == "__main__":
    main()
