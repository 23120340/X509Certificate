"""
ui/customer/my_keys_view.py
---------------------------
Quản lý keypair cá nhân của khách hàng (B.4).

  • Bảng list keypair (newest first)
  • Nút "Sinh keypair mới" → dialog (name + key_size)
  • Nút "Xem public key" → Toplevel hiển thị PEM
  • Nút "Xóa" → confirm + refuse nếu đang được CSR tham chiếu
"""

import tkinter as tk
from tkinter import ttk, messagebox

from services.customer_keys import (
    generate_keypair, list_keys, get_key_meta, delete_key, CustomerKeyError,
)
from services.audit import write_audit, Action


KEY_SIZE_OPTIONS = ("2048", "3072", "4096")


class MyKeysFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Keypair của tôi (B.4)",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Sinh + quản lý các keypair RSA cá nhân. Private key được mã "
                "hóa AES-256-GCM trước khi lưu vào DB. Public key dùng cho "
                "việc gửi CSR cấp chứng chỉ ở mục bên cạnh."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        self._build_toolbar()
        self._build_tree()
        self.refresh()

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(bar, text="🔑 Sinh keypair mới",
                   command=self.open_generate_dialog).pack(side=tk.LEFT)
        ttk.Button(bar, text="📋 Xem public key",
                   command=self.on_view_pubkey).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="🗑 Xóa",
                   command=self.on_delete).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))

    def _build_tree(self) -> None:
        cols = ("id", "name", "algorithm", "key_size", "created_at")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        labels = {
            "id": "ID", "name": "Tên", "algorithm": "Algo",
            "key_size": "Key size", "created_at": "Tạo lúc",
        }
        widths = {"id": 50, "name": 180, "algorithm": 80,
                  "key_size": 80, "created_at": 180}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

    def refresh(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for k in list_keys(self.app.session["id"], self.app.db_path):
            self.tree.insert(
                "", tk.END, iid=str(k["id"]),
                values=(
                    k["id"], k["name"], k["algorithm"], k["key_size"],
                    k["created_at"][:19].replace("T", " "),
                ),
            )

    def _selected_key_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn",
                                    "Hãy chọn keypair trong bảng.")
            return None
        return int(sel[0])

    # ── Actions ───────────────────────────────────────────────────────────────

    def open_generate_dialog(self) -> None:
        GenerateKeypairDialog(self, self.app, on_done=self.refresh)

    def on_view_pubkey(self) -> None:
        key_id = self._selected_key_id()
        if key_id is None:
            return
        meta = get_key_meta(key_id, self.app.session["id"], self.app.db_path)
        if meta is None:
            return
        ViewPublicKeyDialog(self, meta)

    def on_delete(self) -> None:
        key_id = self._selected_key_id()
        if key_id is None:
            return
        meta = get_key_meta(key_id, self.app.session["id"], self.app.db_path)
        if meta is None:
            return
        if not messagebox.askyesno(
            "Xác nhận",
            f"Xóa keypair '{meta['name']}'? Hành động này không hoàn tác được.",
        ):
            return
        try:
            delete_key(key_id, self.app.session["id"], self.app.db_path)
        except CustomerKeyError as e:
            messagebox.showerror("Không xóa được", str(e))
            return
        self.refresh()


class GenerateKeypairDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, app, on_done=None):
        super().__init__(parent)
        self.app = app
        self.on_done = on_done

        self.title("Sinh keypair mới")
        self.geometry("400x230")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Tên keypair:").grid(
            row=0, column=0, sticky="e", pady=6, padx=4
        )
        self.name_entry = ttk.Entry(frame, width=28)
        self.name_entry.grid(row=0, column=1, pady=6, padx=4, sticky="ew")
        self.name_entry.insert(0, "key-1")

        ttk.Label(frame, text="Key size:").grid(
            row=1, column=0, sticky="e", pady=6, padx=4
        )
        self.key_size_var = tk.StringVar(value="2048")
        ks_box = ttk.Frame(frame)
        ks_box.grid(row=1, column=1, sticky="w", pady=6)
        for ks in KEY_SIZE_OPTIONS:
            ttk.Radiobutton(
                ks_box, text=ks, value=ks, variable=self.key_size_var,
            ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(
            frame,
            text="Lưu ý: sinh key 4096 có thể mất vài giây.",
            foreground="#888", font=("Segoe UI", 8),
        ).grid(row=2, column=0, columnspan=2, pady=(8, 0), padx=4, sticky="w")

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=99, column=0, columnspan=2,
                     pady=(16, 0), sticky="e")
        ttk.Button(btn_row, text="Sinh", command=self.on_submit).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(btn_row, text="Hủy", command=self.destroy).pack(
            side=tk.RIGHT, padx=4
        )

        frame.columnconfigure(1, weight=1)
        self.name_entry.focus_set()
        self.name_entry.select_range(0, tk.END)

    def on_submit(self) -> None:
        name = self.name_entry.get().strip()
        try:
            key_size = int(self.key_size_var.get())
        except ValueError:
            messagebox.showerror("Lỗi", "Key size không hợp lệ.")
            return
        try:
            self.config(cursor="watch")
            self.update_idletasks()
            kp = generate_keypair(
                self.app.session["id"], name, key_size, self.app.db_path,
            )
        except CustomerKeyError as e:
            self.config(cursor="")
            messagebox.showerror("Lỗi", str(e))
            return
        finally:
            self.config(cursor="")

        write_audit(
            self.app.db_path, self.app.session["id"], Action.KEY_GENERATED,
            target_type="customer_key", target_id=str(kp["id"]),
            details={"name": name, "key_size": key_size},
        )
        messagebox.showinfo(
            "Thành công",
            f"Đã sinh keypair '{name}' (id={kp['id']}, RSA-{key_size}).",
        )
        if self.on_done:
            self.on_done()
        self.destroy()


class ViewPublicKeyDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, meta: dict):
        super().__init__(parent)
        self.title(f"Public key — {meta['name']}")
        self.geometry("680x420")
        self.transient(parent)

        ttk.Label(
            self,
            text=(
                f"Keypair: {meta['name']}  •  RSA-{meta['key_size']}  •  "
                f"id={meta['id']}"
            ),
            font=("Segoe UI", 10, "bold"),
            padding=(12, 8),
        ).pack(anchor="w")

        text = tk.Text(self, font=("Courier New", 9), wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        pem_str = bytes(meta["public_key_pem"]).decode("ascii", errors="replace")
        text.insert("1.0", pem_str)
        text.config(state=tk.DISABLED)

        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(
            btn_row, text="Copy",
            command=lambda: self._copy(pem_str),
        ).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Đóng", command=self.destroy).pack(side=tk.RIGHT)

    def _copy(self, content: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(content)
