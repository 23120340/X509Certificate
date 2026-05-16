"""
ui/customer/csr_submit_view.py
------------------------------
Submit CSR + xem trạng thái CSR cá nhân (B.5, B.6 phần CSR-side).

Layout:
  • Form trên: chọn keypair (combobox), nhập domain (CN), SAN (CSV), nút Submit.
  • Bảng dưới: danh sách CSR của user (id, CN, status, submitted_at, reviewed_at).
  • Nút "Xem CSR PEM", "Hủy CSR pending".
"""

import tkinter as tk
from tkinter import ttk, messagebox

from services.customer_keys import list_keys
from services.csr_workflow import (
    submit_csr, list_my_csr, get_my_csr_by_id, cancel_csr, CSRError,
)
from services.audit import write_audit, Action


STATUS_COLORS = {
    "pending":  "#d68910",
    "approved": "#1e8449",
    "rejected": "#c0392b",
}


class CSRSubmitFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Yêu cầu cấp Chứng nhận X.509 (B.5-6)",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Tạo CSR (PKCS#10) cho tên miền website của bạn. CSR được ký "
                "bằng private key của keypair bạn chọn — Admin sẽ duyệt và "
                "phát hành chứng chỉ X.509 dựa trên CSR này."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        self._build_form()

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=12)

        ttk.Label(
            self, text="Các CSR của tôi",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        self._build_table()
        self._build_table_actions()

        self.refresh_keys()
        self.refresh_csr_table()

    # ── Form submit CSR ───────────────────────────────────────────────────────

    def _build_form(self) -> None:
        form = ttk.LabelFrame(self, text="Submit CSR mới", padding=12)
        form.pack(fill=tk.X)

        ttk.Label(form, text="Keypair:").grid(
            row=0, column=0, sticky="e", pady=4, padx=4
        )
        self.key_combo = ttk.Combobox(
            form, state="readonly", width=42,
        )
        self.key_combo.grid(row=0, column=1, columnspan=3, pady=4, padx=4,
                            sticky="ew")
        ttk.Button(form, text="↻", width=3, command=self.refresh_keys).grid(
            row=0, column=4, pady=4
        )

        ttk.Label(form, text="Domain (CN):").grid(
            row=1, column=0, sticky="e", pady=4, padx=4
        )
        self.cn_entry = ttk.Entry(form, width=42)
        self.cn_entry.grid(row=1, column=1, columnspan=3, pady=4, padx=4,
                           sticky="ew")
        self.cn_entry.insert(0, "example.com")

        ttk.Label(form, text="SAN (CSV):").grid(
            row=2, column=0, sticky="e", pady=4, padx=4
        )
        self.san_entry = ttk.Entry(form, width=42)
        self.san_entry.grid(row=2, column=1, columnspan=3, pady=4, padx=4,
                            sticky="ew")
        ttk.Label(
            form,
            text="VD: www.example.com, api.example.com  •  để trống = chỉ CN",
            foreground="#888", font=("Segoe UI", 8),
        ).grid(row=3, column=1, columnspan=3, sticky="w", padx=4)

        ttk.Button(form, text="Submit CSR", command=self.on_submit).grid(
            row=4, column=1, pady=(10, 4), sticky="w", padx=4,
        )
        form.columnconfigure(1, weight=1)

    def refresh_keys(self) -> None:
        """Reload list keypair từ DB vào combobox."""
        self._keys = list_keys(self.app.session["id"], self.app.db_path)
        values = [
            f"#{k['id']} — {k['name']} (RSA-{k['key_size']})"
            for k in self._keys
        ]
        self.key_combo["values"] = values
        if values:
            self.key_combo.current(0)
        else:
            self.key_combo.set("")

    def _selected_key_id(self) -> "int | None":
        idx = self.key_combo.current()
        if idx < 0 or idx >= len(self._keys):
            return None
        return self._keys[idx]["id"]

    def on_submit(self) -> None:
        key_id = self._selected_key_id()
        if key_id is None:
            messagebox.showerror(
                "Lỗi",
                "Bạn chưa có keypair nào. Sang mục 'Keypair của tôi' để sinh trước.",
            )
            return
        cn = self.cn_entry.get().strip()
        san_raw = self.san_entry.get().strip()
        san_list = [s.strip() for s in san_raw.split(",")] if san_raw else []

        try:
            csr = submit_csr(
                requester_id=self.app.session["id"],
                customer_key_id=key_id,
                common_name=cn,
                san_list=san_list,
                db_path=self.app.db_path,
            )
        except CSRError as e:
            messagebox.showerror("Submit CSR thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.CSR_SUBMITTED,
            target_type="csr", target_id=str(csr["id"]),
            details={
                "customer_key_id": key_id,
                "common_name": cn,
                "san_list": san_list,
            },
        )
        messagebox.showinfo(
            "Đã submit",
            f"CSR #{csr['id']} cho '{cn}' đã gửi lên Admin để duyệt.",
        )
        self.refresh_csr_table()

    # ── Table CSR của tôi ─────────────────────────────────────────────────────

    def _build_table(self) -> None:
        cols = ("id", "common_name", "san", "key_id", "status",
                "submitted_at", "reviewed_at")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        labels = {
            "id": "ID", "common_name": "Domain (CN)",
            "san": "SAN", "key_id": "KeyID",
            "status": "Status",
            "submitted_at": "Submit lúc", "reviewed_at": "Reviewed lúc",
        }
        widths = {"id": 50, "common_name": 180, "san": 200, "key_id": 60,
                  "status": 80, "submitted_at": 150, "reviewed_at": 150}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)
        for s, color in STATUS_COLORS.items():
            self.tree.tag_configure(s, foreground=color)

    def _build_table_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(bar, text="📋 Xem CSR PEM",
                   command=self.on_view_csr).pack(side=tk.LEFT)
        ttk.Button(bar, text="🗑 Hủy CSR pending",
                   command=self.on_cancel).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="Refresh",
                   command=self.refresh_csr_table).pack(side=tk.LEFT, padx=(8, 0))

    def refresh_csr_table(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for c in list_my_csr(self.app.session["id"], self.app.db_path):
            san_str = ", ".join(c["san_list"]) if c.get("san_list") else "—"
            self.tree.insert(
                "", tk.END, iid=str(c["id"]),
                values=(
                    c["id"], c["common_name"], san_str,
                    c["customer_key_id"], c["status"],
                    c["submitted_at"][:19].replace("T", " "),
                    (c["reviewed_at"] or "")[:19].replace("T", " ") if c["reviewed_at"] else "—",
                ),
                tags=(c["status"],),
            )

    def _selected_csr_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Hãy chọn CSR trong bảng.")
            return None
        return int(sel[0])

    def on_view_csr(self) -> None:
        csr_id = self._selected_csr_id()
        if csr_id is None:
            return
        csr = get_my_csr_by_id(csr_id, self.app.session["id"], self.app.db_path)
        if csr is None:
            return
        ViewCSRPEMDialog(self, csr)

    def on_cancel(self) -> None:
        csr_id = self._selected_csr_id()
        if csr_id is None:
            return
        csr = get_my_csr_by_id(csr_id, self.app.session["id"], self.app.db_path)
        if csr is None:
            return
        if csr["status"] != "pending":
            messagebox.showwarning(
                "Không thể hủy",
                f"CSR đang ở trạng thái '{csr['status']}'. Chỉ hủy được khi pending.",
            )
            return
        if not messagebox.askyesno(
            "Xác nhận", f"Hủy CSR #{csr_id} cho '{csr['common_name']}'?",
        ):
            return
        try:
            cancel_csr(csr_id, self.app.session["id"], self.app.db_path)
        except CSRError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        self.refresh_csr_table()


class ViewCSRPEMDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, csr_record: dict):
        super().__init__(parent)
        self.title(f"CSR #{csr_record['id']} — {csr_record['common_name']}")
        self.geometry("720x520")
        self.transient(parent)

        info = (
            f"ID:        #{csr_record['id']}\n"
            f"Domain:    {csr_record['common_name']}\n"
            f"SAN:       {', '.join(csr_record['san_list']) or '—'}\n"
            f"Status:    {csr_record['status']}"
        )
        if csr_record.get("reject_reason"):
            info += f"\nReason:    {csr_record['reject_reason']}"

        ttk.Label(
            self, text=info, justify=tk.LEFT,
            font=("Courier New", 9), padding=(12, 10),
        ).pack(anchor="w")

        text = tk.Text(self, font=("Courier New", 9), wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        pem = bytes(csr_record["csr_pem"]).decode("ascii", errors="replace")
        text.insert("1.0", pem)
        text.config(state=tk.DISABLED)

        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(
            btn_row, text="Copy",
            command=lambda: self._copy(pem),
        ).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Đóng",
                   command=self.destroy).pack(side=tk.RIGHT)

    def _copy(self, content: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(content)
