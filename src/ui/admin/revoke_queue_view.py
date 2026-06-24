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
from ui.common import fmt_local
from ui.widgets.modal import init_modal, make_button_row
from services.audit import write_audit, Action
from services.revocation_workflow import (
    list_all_revocations, get_revocation_detail,
    approve_revocation, reject_revocation, RevocationWorkflowError,
)
from services.cert_lifecycle import certs_sharing_public_key, CertLifecycleError
from services.crl_publish import DEFAULT_CRL_PATH, DEFAULT_OCSP_DB_PATH


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
                "key_compromise", "reason", "status", "submitted_at")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        labels = {
            "id": "ID", "cert_id": "CertID", "requester": "Requester",
            "common_name": "Domain", "key_compromise": "Lộ khóa",
            "reason": "Reason", "status": "Status", "submitted_at": "Gửi lúc",
        }
        widths = {"id": 50, "cert_id": 60, "requester": 100,
                  "common_name": 150, "key_compromise": 70, "reason": 200,
                  "status": 80, "submitted_at": 140}
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
                    "⚠ Có" if r.get("key_compromise") else "—",
                    (r["reason"] or "")[:60],
                    r["status"],
                    fmt_local(r["submitted_at"]),
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
            f"Lộ khóa:        {'CÓ — sẽ thu hồi mọi cert dùng chung khóa' if rec.get('key_compromise') else 'Không'}\n"
            f"Submitted at:   {fmt_local(rec['submitted_at'])}\n"
            f"Status:         {rec['status']}\n"
            + (f"Reviewed at:    {fmt_local(rec['reviewed_at'])}\n" if rec.get('reviewed_at') else "")
            + (f"Reviewed by:    uid={rec['reviewed_by']}\n" if rec.get('reviewed_by') else "")
            + (f"Cert revoked:   {fmt_local(rec['cert_revoked_at'])}\n" if rec.get('cert_revoked_at') else "")
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
        # Nếu request đánh dấu lộ khóa → cảnh báo cascade + cho biết số cert ảnh hưởng.
        if rec.get("key_compromise"):
            try:
                affected = certs_sharing_public_key(
                    rec["issued_cert_id"], self.app.db_path,
                    only_unrevoked=True, owner_id=rec.get("requester_id"),
                )
                n_affected = len(affected)
            except CertLifecycleError:
                n_affected = 1
            confirm_msg = (
                f"⚠ Request #{req_id} đánh dấu LỘ KHÓA.\n"
                f"Approve sẽ thu hồi TẤT CẢ {n_affected} cert (chưa thu hồi) của "
                f"chủ sở hữu dùng chung khóa với cert #{rec['issued_cert_id']} "
                f"({rec.get('common_name') or '?'}), không chỉ riêng cert này.\n\n"
                "Hành động không thể hoàn tác. Tiếp tục?"
            )
        else:
            confirm_msg = (
                f"Approve request #{req_id}?\n"
                f"Cert #{rec['issued_cert_id']} ({rec.get('common_name') or '?'}) "
                f"sẽ bị đánh dấu REVOKED."
            )
        if not messagebox.askyesno("Xác nhận", confirm_msg):
            return
        try:
            result = approve_revocation(
                req_id, self.app.session["id"], self.app.db_path,
                ocsp_db_path=DEFAULT_OCSP_DB_PATH,
                crl_path=DEFAULT_CRL_PATH,
            )
        except RevocationWorkflowError as e:
            messagebox.showerror("Approve thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.REVOKE_APPROVED,
            target_type="revocation_request", target_id=str(req_id),
            details={
                "cert_id": rec["issued_cert_id"],
                "key_compromise": bool(result.get("key_compromise")),
                "revoked_ids": result.get("revoked_ids"),
                "revoked_count": result.get("revoked_count"),
            },
        )
        if result.get("revoked_count"):
            write_audit(
                self.app.db_path, self.app.session["id"], Action.CERT_REVOKED,
                target_type="cert", target_id=str(rec["issued_cert_id"]),
                details={
                    "via": "revocation_request",
                    "request_id": req_id,
                    "reason": rec["reason"],
                    "mode": "by_key" if result.get("key_compromise") else "single",
                    "revoked_ids": result.get("revoked_ids"),
                    "revoked_count": result.get("revoked_count"),
                },
            )
        compromised = result.get("compromised_key_ids") or []
        if compromised:
            write_audit(
                self.app.db_path, self.app.session["id"], Action.KEY_COMPROMISED,
                target_type="customer_key",
                target_id=",".join(map(str, compromised)),
                details={
                    "compromised_key_ids": compromised,
                    "via": "revocation_request",
                    "request_id": req_id,
                },
            )
        cancelled_csrs = result.get("cancelled_csr_ids") or []
        if cancelled_csrs:
            write_audit(
                self.app.db_path, self.app.session["id"], Action.CSR_REJECTED,
                target_type="csr",
                target_id=",".join(map(str, cancelled_csrs)),
                details={
                    "cancelled_csr_ids": cancelled_csrs,
                    "reason": "key compromised — revocation_request cascade",
                    "via": "revocation_request",
                    "request_id": req_id,
                },
            )
        crl_result = result.get("crl_result")
        crl_error = result.get("crl_error")
        if crl_result:
            write_audit(
                self.app.db_path, self.app.session["id"], Action.CRL_PUBLISHED,
                target_type="crl", target_id=crl_result["crl_path"],
                details={
                    "revoked_count": crl_result["revoked_count"],
                    "source": "auto_after_revoke_approve",
                },
            )
        elif crl_error:
            messagebox.showwarning(
                "Đã approve nhưng chưa publish CRL",
                f"Request #{req_id} đã approve, nhưng chưa cập nhật được CRL:\n{crl_error}",
            )

        if result.get("key_compromise"):
            cert_line = (
                f"Đã thu hồi {result.get('revoked_count', 0)} cert dùng chung khóa "
                f"(lộ khóa)."
                + (f" Đã hủy private key của {len(compromised)} keypair."
                   if compromised else "")
                + (f" Đã hủy {len(cancelled_csrs)} CSR pending dùng chung khóa."
                   if cancelled_csrs else "")
            )
        elif result["cert_was_revoked"]:
            cert_line = "Cert đã revoke."
        else:
            cert_line = "Cert đã được revoke trước đó."
        messagebox.showinfo(
            "Đã approve",
            f"Request #{req_id} đã approve. {cert_line}\n"
            + (
                f"CRL đã tự cập nhật ({crl_result['revoked_count']} serial)."
                if crl_result else
                "Hãy vào mục Cập nhật CRL để publish thủ công."
            ),
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

        frame = init_modal(self, parent=parent,
                           title=f"Reject revocation #{rec['id']}",
                           geometry="440x300")

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

        make_button_row(frame, submit_label="Reject",
                        submit_command=self.on_submit)
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
