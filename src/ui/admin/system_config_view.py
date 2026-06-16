"""
ui/admin/system_config_view.py
------------------------------
Form chỉnh sửa cấu hình hệ thống — đáp ứng A.3.

Các trường:
  default_validity_days   — entry int
  root_ca_validity_days   — entry int
  Khóa + hàm băm mặc định cho Root CA — KeyAlgSelector(show_hash=True): loại
    khóa → size/curve → hàm băm PHÙ HỢP (lọc theo đường cong với ECDSA, khóa ô
    với Ed25519). DÙNG CHUNG đúng widget + cấu hình với dialog "Sinh Root CA
    mới" nên hai nơi LUÔN ĐỒNG BỘ (gồm cả ràng buộc hàm băm). Lưu vào:
    default_key_algorithm + default_key_size(RSA)/default_ec_curve(ECDSA) +
    hash_algorithm (bỏ qua khi Ed25519 — giữ nguyên digest toàn cục cũ).

Bấm "Lưu" → validate → set_config từng key → audit log.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from ui.widgets.keyalg_selector import KeyAlgSelector, spec_from
from services.system_config import (
    get_all_config, set_config, DEFAULTS,
)
from services.audit import write_audit, Action


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

        def add_entry(row: int, key: str, label: str) -> None:
            ttk.Label(form, text=label).grid(
                row=row, column=0, sticky="e", pady=6, padx=(0, 8))
            var = tk.StringVar()
            ttk.Entry(form, textvariable=var, width=26).grid(
                row=row, column=1, sticky="w", pady=6)
            self.widgets[key] = var

        add_entry(0, "default_validity_days", "Hiệu lực cert (ngày):")
        add_entry(1, "root_ca_validity_days", "Hiệu lực Root CA (ngày):")

        # Khóa + HÀM BĂM mặc định cho Root CA — DÙNG CHUNG KeyAlgSelector
        # (show_hash=True) ĐÚNG như dialog "Sinh Root CA mới" → hàm băm bị lọc
        # theo loại khóa/đường cong y hệt, hai nơi không thể lệch nhau.
        ttk.Separator(form, orient=tk.HORIZONTAL).grid(
            row=2, column=0, columnspan=2, sticky="ew", pady=(12, 6))
        ttk.Label(
            form, text="Khóa + hàm băm mặc định cho Root CA mới:",
            font=font("label"),
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self.keyalg = KeyAlgSelector(form, show_hash=True)
        self.keyalg.grid(row=4, column=0, columnspan=2, sticky="w")

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
        # set_hash TRƯỚC set_spec để _on_type_change dùng đúng hash mặc định.
        self.keyalg.set_hash(cfg.get("hash_algorithm", DEFAULTS["hash_algorithm"]))
        self.keyalg.set_spec(spec_from(
            cfg.get("default_key_algorithm", DEFAULTS["default_key_algorithm"]),
            cfg.get("default_key_size", DEFAULTS["default_key_size"]),
            cfg.get("default_ec_curve", DEFAULTS["default_ec_curve"]),
        ))

    def on_reset(self) -> None:
        for key, var in self.widgets.items():
            var.set(DEFAULTS.get(key, ""))
        self.keyalg.set_hash(DEFAULTS["hash_algorithm"])
        self.keyalg.set_spec(spec_from(
            DEFAULTS["default_key_algorithm"], DEFAULTS["default_key_size"],
            DEFAULTS["default_ec_curve"],
        ))
        self.status.config(
            text="Đã đặt lại các giá trị mặc định (chưa lưu).",
            foreground="#888",
        )

    def on_save(self) -> None:
        # Validate int (day) fields
        for int_key in ("default_validity_days", "root_ca_validity_days"):
            value = self.widgets[int_key].get().strip()
            try:
                n = int(value)
            except ValueError:
                messagebox.showerror(
                    "Lỗi", f"Trường '{int_key}' phải là số nguyên (đang là {value!r})."
                )
                return
            if n < 1:
                messagebox.showerror("Lỗi", f"'{int_key}' phải >= 1.")
                return

        # Gom giá trị mới từ widgets + selector khóa (KeyAlgSelector).
        new_values = {key: var.get().strip() for key, var in self.widgets.items()}
        ktype = self.keyalg.type_var.get()   # 'RSA' | 'ECDSA' | 'Ed25519'
        new_values["default_key_algorithm"] = ktype
        if ktype == "RSA":
            new_values["default_key_size"] = self.keyalg.param_var.get()
        elif ktype == "ECDSA":
            new_values["default_ec_curve"] = self.keyalg.param_var.get()
        # Hàm băm lấy từ selector (đã lọc theo loại khóa/đường cong). Ed25519 →
        # get_hash_name()=None → GIỮ NGUYÊN hash_algorithm toàn cục hiện có
        # (digest này vẫn cần cho việc ký bằng khóa RSA/EC khác).
        hash_name = self.keyalg.get_hash_name()
        if hash_name:
            new_values["hash_algorithm"] = hash_name.replace("-", "")

        # Persist + audit (chỉ ghi các key thực sự đổi)
        current = get_all_config(self.app.db_path)
        changed: list[tuple[str, str, str]] = []
        for key, new_val in new_values.items():
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
