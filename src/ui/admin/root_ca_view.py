"""
ui/admin/root_ca_view.py
------------------------
Quản lý Root CA — đáp ứng A.4 (sinh keypair) + A.5 (phát sinh Root cert).

Layout:
  Phần A — Root CA active hiện tại
    • Nếu chưa có:  banner "Chưa có Root CA — bấm nút bên dưới để sinh"
    • Nếu đã có:    bảng thông tin (CN, serial, hiệu lực, người tạo) + nút
                    "Publish ra Trust Store", "Sinh Root CA mới (rotate)"
  Phần B — Lịch sử (table)
    • Liệt kê các Root CA đã từng có (kể cả retired).

Modal "Sinh Root CA":
  - common_name (default = system_config.root_ca_common_name nếu có)
  - key_size (radio 2048/3072/4096)
  - validity_days (entry, default = system_config.root_ca_validity_days)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from services.audit import write_audit, Action
from services.ca_admin import (
    create_root_ca, get_active_root_ca, list_root_ca_history, CAError,
    publish_active_to_trust_store,
)
from services.system_config import get_config, get_int_config


DEFAULT_ROOT_CA_CN = "X509 Demo Root CA"
DEFAULT_TRUST_STORE_DIR = "certs/trust_store"


class RootCAFrame(ttk.Frame):
    """Frame xem/sinh Root CA."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Root Certificate Authority",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Root CA là gốc tin cậy của toàn hệ thống. Mỗi cert phát hành "
                "đều phải được Root CA ký. Private key của Root CA được "
                "encrypt-at-rest (AES-256-GCM) trước khi lưu vào DB."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 16))

        self._active_section = ttk.Frame(self)
        self._active_section.pack(fill=tk.X, anchor="w")

        ttk.Label(
            self, text="Lịch sử Root CA",
            font=font("heading_md"),
        ).pack(anchor="w", pady=(20, 4))
        self._build_history_table()

        self.refresh()

    # ── Active section ────────────────────────────────────────────────────────

    def _render_active(self, ca: "dict | None") -> None:
        for child in self._active_section.winfo_children():
            child.destroy()

        if ca is None:
            box = ttk.LabelFrame(
                self._active_section,
                text="Chưa có Root CA active", padding=12,
            )
            box.pack(fill=tk.X)
            ttk.Label(
                box,
                text=(
                    "Hệ thống chưa có Root CA. Bấm nút bên dưới để sinh "
                    "keypair (RSA) + Root Certificate. Private key sẽ được "
                    "mã hóa AES-GCM trước khi lưu DB."
                ),
                wraplength=680, justify=tk.LEFT, foreground="#444",
            ).pack(anchor="w", pady=(0, 8))
            ttk.Button(
                box, text="🔑 Sinh Root CA",
                command=self.open_generate_dialog,
            ).pack(anchor="w")
            return

        box = ttk.LabelFrame(
            self._active_section,
            text=f"Root CA active — #{ca['id']}", padding=12,
        )
        box.pack(fill=tk.X)

        def row(label: str, value: str) -> None:
            ttk.Label(
                box, text=label, font=font("label"), width=20,
            ).grid(column=0, sticky="w", padx=(0, 8), pady=2)
            ttk.Label(box, text=value).grid(
                column=1, sticky="w", pady=2,
            )

        # grid layout
        for i, (label, key) in enumerate([
            ("Common Name",         "common_name"),
            ("Serial (hex)",        "serial_hex"),
            ("Not Valid Before",    "not_valid_before"),
            ("Not Valid After",     "not_valid_after"),
            ("Created at",          "created_at"),
        ]):
            ttk.Label(
                box, text=label, font=font("label"),
            ).grid(row=i, column=0, sticky="w", padx=(0, 12), pady=2)
            ttk.Label(box, text=str(ca[key])).grid(
                row=i, column=1, sticky="w", pady=2,
            )

        btn_row = ttk.Frame(box)
        btn_row.grid(row=99, column=0, columnspan=2, sticky="w", pady=(12, 0))
        ttk.Button(
            btn_row, text="📁 Publish ra Trust Store",
            command=self.on_publish,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            btn_row, text="🔄 Sinh Root CA mới (rotate)",
            command=self.open_generate_dialog,
        ).pack(side=tk.LEFT)

    # ── History table ─────────────────────────────────────────────────────────

    def _build_history_table(self) -> None:
        cols = ("id", "common_name", "serial", "not_valid_after",
                "created_at", "is_active")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=6)
        labels = {
            "id": "ID", "common_name": "Common Name",
            "serial": "Serial", "not_valid_after": "Hết hạn",
            "created_at": "Tạo lúc", "is_active": "Active",
        }
        widths = {"id": 40, "common_name": 200, "serial": 220,
                  "not_valid_after": 170, "created_at": 170, "is_active": 60}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.pack(fill=tk.X)

    def refresh(self) -> None:
        ca = get_active_root_ca(self.app.db_path)
        self._render_active(ca)

        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for r in list_root_ca_history(self.app.db_path):
            self.tree.insert(
                "", tk.END,
                values=(
                    r["id"], r["common_name"], r["serial_hex"],
                    r["not_valid_after"][:19].replace("T", " "),
                    r["created_at"][:19].replace("T", " "),
                    "✓" if r["is_active"] else "",
                ),
            )

    # ── Actions ───────────────────────────────────────────────────────────────

    def open_generate_dialog(self) -> None:
        GenerateRootCADialog(self, self.app, on_done=self.refresh)

    def on_publish(self) -> None:
        try:
            path = publish_active_to_trust_store(
                self.app.db_path, DEFAULT_TRUST_STORE_DIR,
            )
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            return
        if path:
            messagebox.showinfo(
                "Đã publish",
                f"Đã ghi Root CA cert ra:\n{path}\n\n"
                f"Client/CRL server load file này để verify cert + CRL.",
            )
        else:
            messagebox.showwarning("Chưa có Root CA", "Sinh Root CA trước.")


class GenerateRootCADialog(tk.Toplevel):
    """Modal sinh Root CA mới (lần đầu hoặc rotate)."""

    def __init__(self, parent: tk.Misc, app, on_done=None):
        super().__init__(parent)
        self.app = app
        self.on_done = on_done

        self.title("Sinh Root CA mới")
        self.geometry("440x310")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Lấy default từ system_config
        default_cn = get_config("root_ca_common_name", app.db_path) or DEFAULT_ROOT_CA_CN
        default_key_size = get_int_config("default_key_size", app.db_path, 2048)
        default_validity = get_int_config("root_ca_validity_days", app.db_path, 3650)

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Common Name:").grid(
            row=0, column=0, sticky="e", pady=6, padx=4
        )
        self.cn_entry = ttk.Entry(frame, width=30)
        self.cn_entry.grid(row=0, column=1, pady=6, padx=4, sticky="ew")
        self.cn_entry.insert(0, default_cn)

        ttk.Label(frame, text="Key size (RSA):").grid(
            row=1, column=0, sticky="e", pady=6, padx=4
        )
        self.key_size_var = tk.StringVar(value=str(default_key_size))
        ks_box = ttk.Frame(frame)
        ks_box.grid(row=1, column=1, sticky="w", pady=6)
        for ks in ("2048", "3072", "4096"):
            ttk.Radiobutton(
                ks_box, text=ks, value=ks, variable=self.key_size_var,
            ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(frame, text="Validity (ngày):").grid(
            row=2, column=0, sticky="e", pady=6, padx=4
        )
        self.validity_entry = ttk.Entry(frame, width=12)
        self.validity_entry.grid(row=2, column=1, pady=6, padx=4, sticky="w")
        self.validity_entry.insert(0, str(default_validity))

        # Warning rotate
        has_active = get_active_root_ca(app.db_path) is not None
        if has_active:
            warn = ttk.Label(
                frame,
                text=(
                    "⚠ Hệ thống đã có Root CA active. Sinh Root CA mới sẽ "
                    "deactivate Root CA hiện tại. Các cert đã phát hành "
                    "vẫn còn chữ ký của Root CA cũ — client sẽ FAIL verify "
                    "cho đến khi bạn re-issue cert mới."
                ),
                foreground="#c0392b", wraplength=380, justify=tk.LEFT,
            )
            warn.grid(row=3, column=0, columnspan=2, sticky="w",
                      pady=(12, 0), padx=4)

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=99, column=0, columnspan=2, pady=(16, 0), sticky="e")
        ttk.Button(btn_row, text="Sinh", command=self.on_submit).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(btn_row, text="Hủy", command=self.destroy).pack(
            side=tk.RIGHT, padx=4
        )

        frame.columnconfigure(1, weight=1)
        self.cn_entry.focus_set()

    def on_submit(self) -> None:
        cn = self.cn_entry.get().strip()
        try:
            key_size = int(self.key_size_var.get())
            validity = int(self.validity_entry.get())
        except ValueError:
            messagebox.showerror("Lỗi", "Key size / validity phải là số nguyên.")
            return

        try:
            ca = create_root_ca(
                common_name=cn, key_size=key_size, validity_days=validity,
                created_by=self.app.session["id"], db_path=self.app.db_path,
            )
        except CAError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        except Exception as e:
            messagebox.showerror("Lỗi không lường", f"{type(e).__name__}: {e}")
            return

        action = (Action.ROOT_CA_ROTATED if ca["id"] > 1
                  else Action.ROOT_CA_CREATED)
        write_audit(
            self.app.db_path, self.app.session["id"], action,
            target_type="root_ca", target_id=str(ca["id"]),
            details={
                "common_name":  ca["common_name"],
                "serial_hex":   ca["serial_hex"],
                "key_size":     key_size,
                "validity_days": validity,
            },
        )

        messagebox.showinfo(
            "Thành công",
            f"Đã sinh Root CA mới (#{ca['id']}).\n"
            f"CN: {ca['common_name']}\n"
            f"Serial: {ca['serial_hex']}\n"
            f"Hết hạn: {ca['not_valid_after']}",
        )
        if self.on_done:
            self.on_done()
        self.destroy()
