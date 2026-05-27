"""
ui/customer/revoke_request_view.py
----------------------------------
Customer yêu cầu thu hồi cert (B.7).

Layout:
  • Form: chọn cert active của mình + reason → Submit yêu cầu
  • Bảng: danh sách yêu cầu đã gửi của user (status có màu)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from ui.widgets.modal import init_modal, make_button_row
from services.audit import write_audit, Action
from services.cert_lifecycle import list_certs_for_owner
from services.revocation_workflow import (
    submit_revoke_request, list_my_revocation_requests,
    RevocationWorkflowError,
)
from services.remote_csr_client import (
    list_customer_certs_from_admin_api,
    submit_revocation_to_admin_api,
    list_revocation_requests_from_admin_api,
    RemoteCSRClientError,
)


STATUS_COLORS = {
    "pending":  "#d68910",
    "approved": "#1e8449",
    "rejected": "#c0392b",
}


class RevokeRequestFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app
        self.remote_api_url = getattr(app, "remote_csr_api_url", "")
        self.remote_api_token = getattr(app, "remote_csr_api_token", "")

        ttk.Label(
            self, text="Yêu cầu thu hồi",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Gửi yêu cầu admin thu hồi cert đã cấp cho bạn (vd: key bị "
                "lộ, không còn dùng domain). Admin sẽ duyệt; sau khi approve, "
                "cert sẽ bị đánh dấu revoked và serial xuất hiện trong CRL."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        self._build_form()

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=12)

        ttk.Label(
            self, text="Yêu cầu của tôi",
            font=font("heading_md"),
        ).pack(anchor="w", pady=(0, 4))
        self._build_table()
        self._build_actions()

        self.refresh_certs()
        self.refresh_requests()

    # ── Form submit ───────────────────────────────────────────────────────────

    def _build_form(self) -> None:
        form = ttk.LabelFrame(self, text="Gửi yêu cầu thu hồi", padding=12)
        form.pack(fill=tk.X)

        ttk.Label(form, text="Cert (active):").grid(
            row=0, column=0, sticky="e", pady=4, padx=4,
        )
        self.cert_combo = ttk.Combobox(
            form, state="readonly", width=48,
        )
        self.cert_combo.grid(row=0, column=1, pady=4, padx=4, sticky="ew")
        ttk.Button(form, text="↻", width=3,
                   command=self.refresh_certs).grid(row=0, column=2, pady=4)

        ttk.Label(form, text="Lý do:").grid(
            row=1, column=0, sticky="ne", pady=4, padx=4,
        )
        self.reason_text = tk.Text(form, height=4, width=48, wrap=tk.WORD)
        self.reason_text.grid(row=1, column=1, pady=4, padx=4, sticky="ew")

        submit_row = 2
        if self.remote_api_url:
            ttk.Label(form, text="Mật khẩu customer trên Admin:").grid(
                row=2, column=0, sticky="e", pady=4, padx=4,
            )
            self.remote_password_entry = ttk.Entry(form, width=48, show="*")
            self.remote_password_entry.grid(
                row=2, column=1, pady=4, padx=4, sticky="ew"
            )
            if getattr(self.app, "remote_csr_password", ""):
                self.remote_password_entry.insert(0, self.app.remote_csr_password)
            submit_row = 3

        ttk.Button(form, text="Gửi yêu cầu",
                   command=self.on_submit).grid(
            row=submit_row, column=1, sticky="w", pady=(8, 0), padx=4,
        )
        form.columnconfigure(1, weight=1)

    def refresh_certs(self) -> None:
        """Reload list cert active của user vào combobox."""
        try:
            rows = self._fetch_certs()
        except RemoteCSRClientError as e:
            messagebox.showerror("Không tải được cert từ Admin", str(e))
            rows = []
        self._active_certs = [c for c in rows if c["status"] == "active"]
        values = [
            f"#{c['id']} — {c['common_name']} "
            f"(serial {c['serial_hex'][:12]}…)"
            for c in self._active_certs
        ]
        self.cert_combo["values"] = values
        if values:
            self.cert_combo.current(0)
        else:
            self.cert_combo.set("")

    def _selected_cert_id(self) -> "int | None":
        idx = self.cert_combo.current()
        if idx < 0 or idx >= len(self._active_certs):
            return None
        return self._active_certs[idx]["id"]

    def _remote_password(self) -> str:
        if hasattr(self, "remote_password_entry"):
            password = self.remote_password_entry.get()
            if password:
                self.app.remote_csr_password = password
                return password
        return getattr(self.app, "remote_csr_password", "")

    def _fetch_certs(self) -> list:
        if not self.remote_api_url:
            return list_certs_for_owner(self.app.session["id"], self.app.db_path)
        password = self._remote_password()
        if not password:
            return []
        return list_customer_certs_from_admin_api(
            api_url=self.remote_api_url,
            username=self.app.session["username"],
            password=password,
            status="active",
            token=self.remote_api_token,
        )

    def on_submit(self) -> None:
        cert_id = self._selected_cert_id()
        if cert_id is None:
            messagebox.showerror(
                "Lỗi",
                "Bạn không có cert active nào để yêu cầu thu hồi.",
            )
            return
        reason = self.reason_text.get("1.0", tk.END).strip()
        if self.remote_api_url:
            try:
                req = submit_revocation_to_admin_api(
                    api_url=self.remote_api_url,
                    username=self.app.session["username"],
                    password=self._remote_password(),
                    cert_id=cert_id,
                    reason=reason,
                    token=self.remote_api_token,
                )
            except RemoteCSRClientError as e:
                messagebox.showerror("Gửi yêu cầu thất bại", str(e))
                return
            messagebox.showinfo(
                "Đã gửi", f"Yêu cầu #{req['id']} đã gửi tới admin.",
            )
            self.reason_text.delete("1.0", tk.END)
            self.refresh_certs()
            self.refresh_requests()
            return

        try:
            req = submit_revoke_request(
                cert_id, self.app.session["id"], reason, self.app.db_path,
            )
        except RevocationWorkflowError as e:
            messagebox.showerror("Gửi yêu cầu thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.REVOKE_REQUESTED,
            target_type="revocation_request", target_id=str(req["id"]),
            details={"cert_id": cert_id, "reason": reason},
        )
        messagebox.showinfo(
            "Đã gửi", f"Yêu cầu #{req['id']} đã gửi tới admin.",
        )
        self.reason_text.delete("1.0", tk.END)
        self.refresh_certs()
        self.refresh_requests()

    # ── Table ─────────────────────────────────────────────────────────────────

    def _build_table(self) -> None:
        cols = ("id", "cert_id", "common_name", "reason",
                "status", "submitted_at", "reviewed_at")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        labels = {
            "id": "ID", "cert_id": "CertID", "common_name": "Domain",
            "reason": "Reason", "status": "Status",
            "submitted_at": "Gửi lúc", "reviewed_at": "Duyệt lúc",
        }
        widths = {"id": 50, "cert_id": 60, "common_name": 150,
                  "reason": 220, "status": 80,
                  "submitted_at": 140, "reviewed_at": 140}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)
        for s, color in STATUS_COLORS.items():
            self.tree.tag_configure(s, foreground=color)
        self.tree.bind("<Double-1>", lambda _e: self.on_view_detail())

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(
            bar, text="Xem chi tiết",
            command=self.on_view_detail,
        ).pack(side=tk.LEFT)

    def refresh_requests(self) -> None:
        self._requests_by_id = {}
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        try:
            rows = self._fetch_requests()
        except RemoteCSRClientError as e:
            messagebox.showerror("Không tải được yêu cầu từ Admin", str(e))
            rows = []
        for r in rows:
            self._requests_by_id[int(r["id"])] = r
            reason = r["reason"] or ""
            reason_preview = reason[:60] + ("..." if len(reason) > 60 else "")
            self.tree.insert(
                "", tk.END, iid=str(r["id"]),
                values=(
                    r["id"], r["issued_cert_id"],
                    r.get("common_name") or "—",
                    reason_preview,
                    r["status"],
                    r["submitted_at"][:19].replace("T", " "),
                    (r["reviewed_at"] or "—")[:19].replace("T", " ") if r["reviewed_at"] else "—",
                ),
                tags=(r["status"],),
            )

    def _fetch_requests(self) -> list:
        if not self.remote_api_url:
            return list_my_revocation_requests(
                self.app.session["id"], self.app.db_path,
            )
        password = self._remote_password()
        if not password:
            return []
        return list_revocation_requests_from_admin_api(
            api_url=self.remote_api_url,
            username=self.app.session["username"],
            password=password,
            token=self.remote_api_token,
        )

    def _selected_request(self) -> "dict | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning(
                "Chưa chọn",
                "Hãy chọn một yêu cầu thu hồi trong bảng.",
            )
            return None
        return self._requests_by_id.get(int(sel[0]))

    def on_view_detail(self) -> None:
        rec = self._selected_request()
        if rec is None:
            return
        RevocationRequestDetailDialog(self, rec)


class RevocationRequestDetailDialog(tk.Toplevel):
    """Dialog cho customer xem đầy đủ reason / reject reason của request."""

    def __init__(self, parent: tk.Misc, rec: dict):
        super().__init__(parent)
        self.rec = rec
        frame = init_modal(
            self,
            parent=parent,
            title=f"Chi tiết yêu cầu thu hồi #{rec['id']}",
            geometry="680x520",
            resizable=True,
        )
        self._build_content(frame)
        make_button_row(frame, cancel_label="Đóng")

    def _build_content(self, frame: ttk.Frame) -> None:
        rec = self.rec
        info = (
            f"Request ID:    #{rec['id']}\n"
            f"Cert ID:       #{rec['issued_cert_id']}\n"
            f"Domain:        {rec.get('common_name') or '—'}\n"
            f"Serial:        {rec.get('serial_hex') or '—'}\n"
            f"Status:        {rec['status']}\n"
            f"Gửi lúc:       {rec['submitted_at']}\n"
            f"Duyệt lúc:     {rec.get('reviewed_at') or '—'}\n"
            f"Reviewed by:   {rec.get('reviewed_by') or '—'}\n"
        )
        ttk.Label(frame, text=info, justify=tk.LEFT, font=font("mono")).pack(
            anchor="w", fill=tk.X, pady=(0, 10),
        )

        ttk.Label(
            frame,
            text="Reason / Reject reason đầy đủ:",
            font=font("heading_md"),
        ).pack(anchor="w", pady=(0, 4))

        body = ttk.Frame(frame)
        body.pack(fill=tk.BOTH, expand=True)
        text = tk.Text(body, wrap=tk.WORD, height=12, font=font("mono"))
        yscroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=yscroll.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        text.insert("1.0", rec.get("reason") or "—")
        text.config(state=tk.DISABLED)
