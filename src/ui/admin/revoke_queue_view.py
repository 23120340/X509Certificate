"""
ui/admin/revoke_queue_view.py
-----------------------------
Admin duyệt yêu cầu thu hồi (A.9).

  • Bảng tất cả request + filter status (default pending)
  • Xem chi tiết + Approve / Reject (reason bắt buộc cho reject)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from services.audit import write_audit, Action
from services.revocation_workflow import (
    list_all_revocations, get_revocation_detail,
    approve_revocation, reject_revocation, RevocationWorkflowError,
)


STATUS_COLORS = {
    "pending":  "#d68910",
    "approved": "#1e8449",
    "rejected": "#c0392b",
}


class RevokeQueueFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Duyệt yêu cầu thu hồi",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Approve sẽ đánh dấu cert revoked NGAY trong DB. CRL/OCSP "
                "sẽ phản ánh sau khi Admin bấm Publish CRL."
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
            bar, values=("pending", "approved", "rejected", "all"),
            state="readonly", width=12,
        )
        self.status_combo.current(0)
        self.status_combo.pack(side=tk.LEFT)
        self.status_combo.bind("<<ComboboxSelected>>",
                               lambda e: self.refresh())
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))
        self.count_label = ttk.Label(bar, text="", foreground="#666")
        self.count_label.pack(side=tk.RIGHT)

    def _build_tree(self) -> None:
        cols = ("id", "cert_id", "requester", "common_name",
                "reason", "status", "submitted_at")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        labels = {
            "id": "ID", "cert_id": "CertID", "requester": "Requester",
            "common_name": "Domain", "reason": "Reason",
            "status": "Status", "submitted_at": "Gửi lúc",
        }
        widths = {"id": 50, "cert_id": 60, "requester": 100,
                  "common_name": 150, "reason": 220, "status": 80,
                  "submitted_at": 140}
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
        ttk.Button(bar, text="✅ Approve",
                   command=self.on_approve).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="❌ Reject",
                   command=self.on_reject).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        status = self.status_combo.get()
        items = list_all_revocations(
            self.app.db_path,
            status=None if status == "all" else status,
        )
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for r in items:
            self.tree.insert(
                "", tk.END, iid=str(r["id"]),
                values=(
                    r["id"], r["issued_cert_id"],
                    r.get("requester_username") or f"uid={r['requester_id']}",
                    r.get("common_name") or "—",
                    (r["reason"] or "")[:60],
                    r["status"],
                    r["submitted_at"][:19].replace("T", " "),
                ),
                tags=(r["status"],),
            )
        self.count_label.config(text=f"{len(items)} request(s)")

    def _selected_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn",
                                    "Hãy chọn request trong bảng.")
            return None
        return int(sel[0])

    def on_view(self) -> None:
        req_id = self._selected_id()
        if req_id is None:
            return
        rec = get_revocation_detail(req_id, self.app.db_path)
        if rec is None:
            return
        info = (
            f"Request #{rec['id']}\n"
            f"Cert ID:        {rec['issued_cert_id']} "
            f"(serial {rec.get('serial_hex', '?')[:24]}…)\n"
            f"Domain:         {rec.get('common_name') or '—'}\n"
            f"Requester:      {rec.get('requester_username') or rec['requester_id']}\n"
            f"Submitted at:   {rec['submitted_at']}\n"
            f"Status:         {rec['status']}\n"
            + (f"Reviewed at:    {rec['reviewed_at']}\n" if rec.get('reviewed_at') else "")
            + (f"Reviewed by:    uid={rec['reviewed_by']}\n" if rec.get('reviewed_by') else "")
            + (f"Cert revoked:   {rec['cert_revoked_at']}\n" if rec.get('cert_revoked_at') else "")
            + f"\nReason:\n{rec.get('reason') or '—'}"
        )
        messagebox.showinfo(f"Request #{req_id}", info)

    def on_approve(self) -> None:
        req_id = self._selected_id()
        if req_id is None:
            return
        rec = get_revocation_detail(req_id, self.app.db_path)
        if rec is None:
            return
        if rec["status"] != "pending":
            messagebox.showwarning(
                "Không thể approve",
                f"Request đang ở status '{rec['status']}'.",
            )
            return
        if not messagebox.askyesno(
            "Xác nhận",
            f"Approve request #{req_id}?\n"
            f"Cert #{rec['issued_cert_id']} ({rec.get('common_name') or '?'}) "
            f"sẽ bị đánh dấu REVOKED.",
        ):
            return
        try:
            result = approve_revocation(
                req_id, self.app.session["id"], self.app.db_path,
            )
        except RevocationWorkflowError as e:
            messagebox.showerror("Approve thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.REVOKE_APPROVED,
            target_type="revocation_request", target_id=str(req_id),
            details={"cert_id": rec["issued_cert_id"]},
        )
        if result["cert_was_revoked"]:
            write_audit(
                self.app.db_path, self.app.session["id"], Action.CERT_REVOKED,
                target_type="cert", target_id=str(rec["issued_cert_id"]),
                details={
                    "via": "revocation_request",
                    "request_id": req_id,
                    "reason": rec["reason"],
                },
            )
        messagebox.showinfo(
            "Đã approve",
            f"Request #{req_id} đã approve. "
            f"Cert {'đã revoke' if result['cert_was_revoked'] else 'đã được revoke trước đó'}.\n"
            f"Đừng quên bấm 'Publish CRL Now' để cập nhật CRL/OCSP.",
        )
        self.refresh()

    def on_reject(self) -> None:
        req_id = self._selected_id()
        if req_id is None:
            return
        rec = get_revocation_detail(req_id, self.app.db_path)
        if rec is None:
            return
        if rec["status"] != "pending":
            messagebox.showwarning(
                "Không thể reject",
                f"Request đang ở status '{rec['status']}'.",
            )
            return
        RejectRevocationDialog(self, self.app, rec, on_done=self.refresh)


class RejectRevocationDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, app, rec: dict, on_done=None):
        super().__init__(parent)
        self.app = app
        self.rec = rec
        self.on_done = on_done

        self.title(f"Reject revocation #{rec['id']}")
        self.geometry("440x260")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=f"Từ chối yêu cầu thu hồi:\n"
                 f"  Request #{rec['id']} cho cert #{rec['issued_cert_id']}\n"
                 f"  Domain: {rec.get('common_name') or '?'}\n",
            justify=tk.LEFT, font=font("body"),
        ).pack(anchor="w")

        ttk.Label(
            frame, text="Lý do từ chối (bắt buộc):",
        ).pack(anchor="w", pady=(8, 4))
        self.reason_text = tk.Text(frame, height=5, width=44, wrap=tk.WORD)
        self.reason_text.pack(fill=tk.BOTH, expand=True)

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_row, text="Reject",
                   command=self.on_submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text="Hủy",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)
        self.reason_text.focus_set()

    def on_submit(self) -> None:
        reason = self.reason_text.get("1.0", tk.END).strip()
        try:
            reject_revocation(
                self.rec["id"], self.app.session["id"],
                reason, self.app.db_path,
            )
        except RevocationWorkflowError as e:
            messagebox.showerror("Reject thất bại", str(e))
            return
        write_audit(
            self.app.db_path, self.app.session["id"], Action.REVOKE_REJECTED,
            target_type="revocation_request", target_id=str(self.rec["id"]),
            details={"reason": reason},
        )
        messagebox.showinfo("Đã reject", f"Request #{self.rec['id']} đã reject.")
        if self.on_done:
            self.on_done()
        self.destroy()
