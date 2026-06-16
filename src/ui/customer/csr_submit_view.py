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

from ui.theme import font
from ui.common import fmt_local
from ui.widgets.modal import fit_to_content
from core.csr import build_csr, csr_to_pem
from services.customer_keys import list_keys, load_private_key, CustomerKeyError
from services.csr_workflow import (
    submit_csr, list_my_csr, get_my_csr_by_id, cancel_csr, CSRError,
)
from services.audit import write_audit, Action
from services.remote_csr_client import (
    check_admin_api_health,
    submit_csr_to_admin_api,
    list_customer_csrs_from_admin_api,
    get_customer_csr_detail_from_admin_api,
    RemoteCSRClientError,
)


STATUS_COLORS = {
    "pending":  "#d68910",
    "approved": "#1e8449",
    "rejected": "#c0392b",
}


class CSRSubmitFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app
        self.remote_api_url = getattr(app, "remote_csr_api_url", "")
        self.remote_api_token = getattr(app, "remote_csr_api_token", "")

        ttk.Label(
            self, text="Yêu cầu cấp Chứng nhận X.509",
            font=font("heading_lg"),
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
            font=font("heading_md"),
        ).pack(anchor="w", pady=(0, 4))
        self._build_table_actions()
        self._build_table()

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
            foreground="#888", font=font("caption"),
        ).grid(row=3, column=1, columnspan=3, sticky="w", padx=4)

        submit_row = 6 if self.remote_api_url else 4
        ttk.Button(form, text="Submit CSR", command=self.on_submit).grid(
            row=submit_row, column=1, pady=(10, 4), sticky="w", padx=4,
        )
        if self.remote_api_url:
            ttk.Label(form, text="Admin API:").grid(
                row=4, column=0, sticky="e", pady=4, padx=4
            )
            self.remote_url_entry = ttk.Entry(form, width=42)
            self.remote_url_entry.grid(
                row=4, column=1, columnspan=3, pady=4, padx=4, sticky="ew"
            )
            self.remote_url_entry.insert(0, self.remote_api_url)
            ttk.Button(
                form, text="Test API", command=self.on_test_remote_api,
            ).grid(row=4, column=4, pady=4, padx=(4, 0))
            ttk.Label(form, text="Mật khẩu customer trên Admin:").grid(
                row=5, column=0, sticky="e", pady=4, padx=4
            )
            self.remote_password_entry = ttk.Entry(form, width=42, show="*")
            self.remote_password_entry.grid(
                row=5, column=1, columnspan=3, pady=4, padx=4, sticky="ew"
            )
            if getattr(self.app, "remote_csr_password", ""):
                self.remote_password_entry.insert(0, self.app.remote_csr_password)
            ttk.Label(
                form,
                text="Remote mode: CSR sẽ gửi qua LAN tới máy Admin; private key vẫn ở máy này.",
                foreground="#666", font=font("caption"),
            ).grid(row=6, column=2, columnspan=2, sticky="w", padx=4)
        form.columnconfigure(1, weight=1)

    def refresh_keys(self) -> None:
        """Reload list keypair từ DB vào combobox."""
        self._keys = [
            k for k in list_keys(self.app.session["id"], self.app.db_path)
            if not k.get("is_public_only")
        ]
        values = [
            f"#{k['id']} — {k['name']} ({k.get('algorithm', 'RSA')}"
            + (f"-{k['key_size']}" if k.get('key_size') else "") + ")"
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

    def _selected_key_meta(self) -> "dict | None":
        idx = self.key_combo.current()
        if idx < 0 or idx >= len(self._keys):
            return None
        return self._keys[idx]

    def on_test_remote_api(self) -> None:
        if not self.remote_api_url:
            return
        api_url = self.remote_url_entry.get().strip()
        try:
            data = check_admin_api_health(api_url=api_url)
        except RemoteCSRClientError as e:
            messagebox.showerror("Không kết nối được Admin API", str(e))
            return
        messagebox.showinfo(
            "Admin API OK",
            f"Kết nối thành công tới {api_url}\nService: {data.get('service', 'csr-api')}",
        )

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

        if self.remote_api_url:
            self._submit_remote(key_id, cn, san_list)
            return

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

    def _submit_remote(self, key_id: int, cn: str, san_list: list[str]) -> None:
        key_meta = self._selected_key_meta()
        api_url = self.remote_url_entry.get().strip()
        password = self.remote_password_entry.get()
        if not password:
            messagebox.showerror(
                "Thiếu mật khẩu",
                "Nhập mật khẩu customer trên máy Admin để gửi CSR qua LAN.",
            )
            return
        try:
            private_key = load_private_key(
                key_id, self.app.session["id"], self.app.db_path,
            )
            csr_obj = build_csr(private_key, common_name=cn, san_list=san_list)
            csr_pem = csr_to_pem(csr_obj)
            rec = submit_csr_to_admin_api(
                api_url=api_url,
                username=self.app.session["username"],
                password=password,
                key_name=(key_meta or {}).get("name", f"key-{key_id}"),
                csr_pem=csr_pem,
                token=self.remote_api_token,
            )
            self.app.set_remote_csr_api(api_url, self.remote_api_token)
            self.app.remote_csr_password = password
            self.refresh_csr_table()
        except (CustomerKeyError, ValueError, RemoteCSRClientError) as e:
            messagebox.showerror("Submit CSR qua LAN thất bại", str(e))
            return

        messagebox.showinfo(
            "Đã gửi CSR qua LAN",
            (
                f"CSR #{rec['id']} cho '{rec['common_name']}' đã gửi tới máy Admin.\n"
                "Admin refresh mục Duyệt CSR để approve/reject."
            ),
        )

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
        bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(6, 0))
        ttk.Button(bar, text="📋 Xem CSR PEM",
                   command=self.on_view_csr).pack(side=tk.LEFT)
        ttk.Button(bar, text="🗑 Hủy CSR pending",
                   command=self.on_cancel).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="Refresh",
                   command=self.refresh_csr_table).pack(side=tk.LEFT, padx=(8, 0))

    def refresh_csr_table(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        try:
            rows = self._fetch_csr_rows()
        except RemoteCSRClientError as e:
            messagebox.showerror("Không tải được CSR từ Admin", str(e))
            return
        for c in rows:
            san_str = ", ".join(c["san_list"]) if c.get("san_list") else "—"
            self.tree.insert(
                "", tk.END, iid=str(c["id"]),
                values=(
                    c["id"], c["common_name"], san_str,
                    c["customer_key_id"], c["status"],
                    fmt_local(c["submitted_at"]),
                    fmt_local(c["reviewed_at"]) if c["reviewed_at"] else "—",
                ),
                tags=(c["status"],),
            )

    def _remote_password(self) -> str:
        if hasattr(self, "remote_password_entry"):
            password = self.remote_password_entry.get()
            if password:
                self.app.remote_csr_password = password
                return password
        return getattr(self.app, "remote_csr_password", "")

    def _fetch_csr_rows(self) -> list:
        if not self.remote_api_url:
            return list_my_csr(self.app.session["id"], self.app.db_path)
        password = self._remote_password()
        if not password:
            return []
        return list_customer_csrs_from_admin_api(
            api_url=self.remote_api_url,
            username=self.app.session["username"],
            password=password,
            token=self.remote_api_token,
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
        if self.remote_api_url:
            try:
                csr = get_customer_csr_detail_from_admin_api(
                    api_url=self.remote_api_url,
                    username=self.app.session["username"],
                    password=self._remote_password(),
                    csr_id=csr_id,
                    token=self.remote_api_token,
                )
            except RemoteCSRClientError as e:
                messagebox.showerror("Không tải được CSR từ Admin", str(e))
                return
        else:
            csr = get_my_csr_by_id(csr_id, self.app.session["id"], self.app.db_path)
        if csr is None:
            return
        ViewCSRPEMDialog(self, csr)

    def on_cancel(self) -> None:
        csr_id = self._selected_csr_id()
        if csr_id is None:
            return
        if self.remote_api_url:
            messagebox.showinfo(
                "Remote mode",
                "CSR đang nằm trên máy Admin. Nếu cần hủy, thực hiện trong demo offline/local.",
            )
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
        write_audit(
            self.app.db_path, self.app.session["id"], Action.CSR_CANCELLED,
            target_type="csr", target_id=str(csr_id),
            details={"common_name": csr["common_name"]},
        )
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
            font=font("mono"), padding=(12, 10),
        ).pack(anchor="w")

        text = tk.Text(self, font=font("mono"), wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        raw_pem = csr_record["csr_pem"]
        pem = (
            raw_pem if isinstance(raw_pem, str)
            else bytes(raw_pem).decode("ascii", errors="replace")
        )
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
        fit_to_content(self)

    def _copy(self, content: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(content)
