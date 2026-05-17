"""
ui/customer/my_certs_view.py
----------------------------
Khách hàng xem + tải chứng chỉ của mình — đáp ứng B.6.

  • Bảng cert của user (status có màu)
  • Filter status (active/expired/revoked/all)
  • View chi tiết (PEM + decoded) + Save As (download)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from services.cert_lifecycle import list_certs_for_owner, get_cert_detail
from ui.common import CertDetailDialog


STATUS_COLORS = {
    "active":  "#1e8449",
    "expired": "#888888",
    "revoked": "#c0392b",
}


class MyCertsFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Chứng nhận của tôi",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Danh sách cert đã được admin phê duyệt + phát hành cho bạn. "
                "Có thể xem chi tiết, copy PEM hoặc tải về máy."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        self._build_toolbar()
        self._build_tree()
        self._build_actions()
        self.refresh()

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT, padx=(0, 4))
        self.status_combo = ttk.Combobox(
            bar, values=("active", "expired", "revoked", "all"),
            state="readonly", width=12,
        )
        self.status_combo.current(3)
        self.status_combo.pack(side=tk.LEFT)
        self.status_combo.bind("<<ComboboxSelected>>",
                               lambda e: self.refresh())
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))
        self.count_label = ttk.Label(bar, text="", foreground="#666")
        self.count_label.pack(side=tk.RIGHT)

    def _build_tree(self) -> None:
        cols = ("id", "common_name", "serial", "status",
                "not_valid_before", "not_valid_after")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        labels = {
            "id": "ID", "common_name": "Domain (CN)",
            "serial": "Serial", "status": "Status",
            "not_valid_before": "Hiệu lực từ",
            "not_valid_after": "Đến",
        }
        widths = {"id": 50, "common_name": 180, "serial": 220,
                  "status": 80,
                  "not_valid_before": 140, "not_valid_after": 140}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        vsb.place(in_=self.tree, relx=1.0, x=-1, rely=0, relheight=1.0,
                  anchor="ne")

        for s, color in STATUS_COLORS.items():
            self.tree.tag_configure(s, foreground=color)

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(bar, text="📋 Xem chi tiết",
                   command=self.on_view).pack(side=tk.LEFT)
        ttk.Button(bar, text="💾 Tải về (Save as)",
                   command=self.on_download).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        status = self.status_combo.get()
        items = list_certs_for_owner(
            self.app.session["id"], self.app.db_path,
            status=None if status == "all" else status,
        )
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for c in items:
            self.tree.insert(
                "", tk.END, iid=str(c["id"]),
                values=(
                    c["id"], c["common_name"],
                    c["serial_hex"][:32] + ("…" if len(c["serial_hex"]) > 32 else ""),
                    c["status"],
                    c["not_valid_before"][:19].replace("T", " "),
                    c["not_valid_after"][:19].replace("T", " "),
                ),
                tags=(c["status"],),
            )
        self.count_label.config(text=f"{len(items)} cert")

    def _selected_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Hãy chọn cert trong bảng.")
            return None
        return int(sel[0])

    def on_view(self) -> None:
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = get_cert_detail(cert_id, self.app.db_path,
                              owner_id=self.app.session["id"])
        if rec is None:
            messagebox.showerror("Lỗi", "Không tìm thấy cert.")
            return
        CertDetailDialog(self, rec)

    def on_download(self) -> None:
        from tkinter import filedialog
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = get_cert_detail(cert_id, self.app.db_path,
                              owner_id=self.app.session["id"])
        if rec is None:
            return
        default_name = (
            f"{rec['common_name']}-{rec['serial_hex'][:8]}.crt"
        )
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Lưu cert PEM",
            defaultextension=".crt",
            initialfile=default_name,
            filetypes=(("PEM cert", "*.crt *.pem"), ("All files", "*.*")),
        )
        if not path:
            return
        with open(path, "wb") as f:
            f.write(bytes(rec["cert_pem"]))
        messagebox.showinfo("Đã lưu", f"Đã lưu cert vào:\n{path}")
