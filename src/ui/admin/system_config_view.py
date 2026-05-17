"""
ui/admin/system_config_view.py
------------------------------
Form chỉnh sửa cấu hình hệ thống — đáp ứng A.3.

5 trường (whitelist từ services/system_config.DEFAULTS):
  sig_algorithm           — dropdown
  hash_algorithm          — dropdown
  default_key_size        — dropdown (2048/3072/4096)
  default_validity_days   — entry int
  root_ca_validity_days   — entry int

Bấm "Lưu" → validate → set_config từng key → audit log.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from services.system_config import (
    get_all_config, set_config, DEFAULTS,
)
from services.audit import write_audit, Action


SIG_ALGO_OPTIONS  = ("RSA-SHA256", "RSA-SHA384", "RSA-SHA512")
HASH_ALGO_OPTIONS = ("SHA256", "SHA384", "SHA512")
KEY_SIZE_OPTIONS  = ("2048", "3072", "4096")


class SystemConfigFrame(ttk.Frame):
    """Form xem + sửa các default config của hệ thống."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Cấu hình hệ thống",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Các tham số mặc định khi phát hành chứng chỉ. Áp dụng cho "
                "Root CA + cert phát hành sau khi cập nhật. Cert đã phát "
                "hành KHÔNG bị ảnh hưởng."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 16))

        self._build_form()
        self._build_actions()
        self._load_from_db()

    # ── Form ──────────────────────────────────────────────────────────────────

    def _build_form(self) -> None:
        form = ttk.Frame(self)
        form.pack(anchor="w")
        self.widgets: dict[str, tk.Variable] = {}

        def add_row(row: int, key: str, label: str,
                    widget_kind: str, options=None) -> None:
            ttk.Label(form, text=label).grid(
                row=row, column=0, sticky="e", pady=6, padx=(0, 8)
            )
            var = tk.StringVar()
            if widget_kind == "combo":
                w = ttk.Combobox(
                    form, textvariable=var, values=options,
                    state="readonly", width=24,
                )
            else:  # entry
                w = ttk.Entry(form, textvariable=var, width=26)
            w.grid(row=row, column=1, sticky="w", pady=6)
            self.widgets[key] = var
            return w

        add_row(0, "sig_algorithm",         "Thuật toán chữ ký:",     "combo",
                SIG_ALGO_OPTIONS)
        add_row(1, "hash_algorithm",        "Hàm băm:",               "combo",
                HASH_ALGO_OPTIONS)
        add_row(2, "default_key_size",      "Độ dài khóa (RSA):",     "combo",
                KEY_SIZE_OPTIONS)
        add_row(3, "default_validity_days", "Hiệu lực cert (ngày):",  "entry")
        add_row(4, "root_ca_validity_days", "Hiệu lực Root CA (ngày):", "entry")

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(anchor="w", pady=(16, 0))
        ttk.Button(bar, text="Lưu",        command=self.on_save).pack(side=tk.LEFT)
        ttk.Button(bar, text="Đặt mặc định", command=self.on_reset).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self.status = ttk.Label(self, text="", foreground="#1e8449")
        self.status.pack(anchor="w", pady=(8, 0))

    # ── Load / save ───────────────────────────────────────────────────────────

    def _load_from_db(self) -> None:
        cfg = get_all_config(self.app.db_path)
        for key, var in self.widgets.items():
            var.set(cfg.get(key, DEFAULTS.get(key, "")))

    def on_reset(self) -> None:
        for key, var in self.widgets.items():
            var.set(DEFAULTS.get(key, ""))
        self.status.config(
            text="Đã đặt lại các giá trị mặc định (chưa lưu).",
            foreground="#888",
        )

    def on_save(self) -> None:
        # Validate int fields
        for int_key in ("default_validity_days", "root_ca_validity_days",
                        "default_key_size"):
            value = self.widgets[int_key].get().strip()
            try:
                n = int(value)
            except ValueError:
                messagebox.showerror(
                    "Lỗi", f"Trường '{int_key}' phải là số nguyên (đang là {value!r})."
                )
                return
            if int_key == "default_key_size" and n not in (2048, 3072, 4096):
                messagebox.showerror(
                    "Lỗi", "default_key_size phải là 2048, 3072 hoặc 4096."
                )
                return
            if int_key.endswith("_days") and n < 1:
                messagebox.showerror(
                    "Lỗi", f"'{int_key}' phải >= 1."
                )
                return

        # Persist + audit
        current = get_all_config(self.app.db_path)
        changed: list[tuple[str, str, str]] = []
        for key, var in self.widgets.items():
            new_val = var.get().strip()
            if current.get(key) != new_val:
                changed.append((key, current.get(key, ""), new_val))
                set_config(key, new_val, self.app.session["id"],
                           self.app.db_path)

        if changed:
            write_audit(
                self.app.db_path, self.app.session["id"], Action.CONFIG_UPDATED,
                target_type="config",
                target_id=",".join(c[0] for c in changed),
                details={k: {"old": old, "new": new} for k, old, new in changed},
            )
            self.status.config(
                text=f"Đã lưu {len(changed)} thay đổi.",
                foreground="#1e8449",
            )
        else:
            self.status.config(
                text="Không có thay đổi nào.",
                foreground="#888",
            )
