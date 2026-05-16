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

from services.audit import write_audit, Action
from services.cert_lifecycle import list_certs_for_owner
from services.revocation_workflow import (
    submit_revoke_request, list_my_revocation_requests,
    RevocationWorkflowError,
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

        ttk.Label(
            self, text="Yêu cầu thu hồi (B.7)",
            font=("Segoe UI", 14, "bold"),
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
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        self._build_table()

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

        ttk.Button(form, text="Gửi yêu cầu",
                   command=self.on_submit).grid(
            row=2, column=1, sticky="w", pady=(8, 0), padx=4,
        )
        form.columnconfigure(1, weight=1)

    def refresh_certs(self) -> None:
        """Reload list cert active của user vào combobox."""
        self._active_certs = [
            c for c in list_certs_for_owner(
                self.app.session["id"], self.app.db_path,
            )
            if c["status"] == "active"
        ]
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

    def on_submit(self) -> None:
        cert_id = self._selected_cert_id()
        if cert_id is None:
            messagebox.showerror(
                "Lỗi",
                "Bạn không có cert active nào để yêu cầu thu hồi.",
            )
            return
        reason = self.reason_text.get("1.0", tk.END).strip()
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

    def refresh_requests(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for r in list_my_revocation_requests(
            self.app.session["id"], self.app.db_path,
        ):
            self.tree.insert(
                "", tk.END, iid=str(r["id"]),
                values=(
                    r["id"], r["issued_cert_id"],
                    r.get("common_name") or "—",
                    (r["reason"] or "")[:60],
                    r["status"],
                    r["submitted_at"][:19].replace("T", " "),
                    (r["reviewed_at"] or "—")[:19].replace("T", " ") if r["reviewed_at"] else "—",
                ),
                tags=(r["status"],),
            )
