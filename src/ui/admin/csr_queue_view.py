"""
ui/admin/csr_queue_view.py
--------------------------
Queue duyệt CSR cho admin (A.6 từ chối + A.7 phê duyệt).

  • Combobox filter status (pending / approved / rejected / all). Default = pending.
  • Bảng list CSR + ai gửi + status (có màu).
  • "Xem chi tiết"  → modal hiển thị CSR PEM + decoded info.
  • "Approve"       → modal nhập validity_days → phát hành cert.
  • "Reject"        → modal nhập reason.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from ui.widgets.status_table import StatusFilterTreeFrame
from ui.widgets.modal import init_modal, make_button_row
from services.audit import write_audit, Action
from services.csr_admin import (
    list_all_csr, get_csr_detail, approve_csr, reject_csr, CSRAdminError,
)
from services.system_config import get_int_config


STATUS_COLORS = {
    "pending":  "#d68910",
    "approved": "#1e8449",
    "rejected": "#c0392b",
}


class CSRQueueFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Duyệt CSR",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Queue CSR khách hàng gửi lên. Trước khi approve, hệ thống "
                "tự verify chữ ký CSR (proof of possession). Approve sẽ phát "
                "hành cert end-entity ký bởi Root CA active hiện tại."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        # Pack actions TRƯỚC table với side=BOTTOM → Tk reserve space cho
        # action bar trước, table mới fill phần còn lại. Nếu pack ngược lại,
        # table fill=BOTH+expand=True sẽ ăn hết, đẩy bar ra ngoài viewport.
        self._build_actions()
        self._build_table()
        self.refresh()

    def _build_table(self) -> None:
        self.table = StatusFilterTreeFrame(
            self,
            columns=[
                ("id",           "ID",          50),
                ("requester",    "Requester",  110),
                ("common_name",  "Domain (CN)", 180),
                ("san",          "SAN",         220),
                ("status",       "Status",       80),
                ("submitted_at", "Submit",      140),
                ("reviewed_at",  "Reviewed",    140),
            ],
            status_values=("pending", "approved", "rejected", "all"),
            status_colors=STATUS_COLORS,
            default_status_index=0,
            fetch_fn=self._fetch_csrs,
            row_mapper=self._csr_to_values,
            count_unit="CSR",
        )
        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.bind_double_click(self.on_view)

    def _fetch_csrs(self, status: str) -> list:
        return list_all_csr(
            self.app.db_path,
            status=None if status == "all" else status,
        )

    def _csr_to_values(self, c: dict) -> tuple:
        san_str = ", ".join(c["san_list"]) if c["san_list"] else "—"
        reviewed = (
            c["reviewed_at"][:19].replace("T", " ")
            if c.get("reviewed_at") else "—"
        )
        return (
            c["id"],
            c.get("requester_username") or f"uid={c['requester_id']}",
            c["common_name"], san_str, c["status"],
            c["submitted_at"][:19].replace("T", " "),
            reviewed,
        )

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(8, 0))
        ttk.Button(bar, text="📋 Xem chi tiết",
                   command=self.on_view).pack(side=tk.LEFT)
        ttk.Button(bar, text="✅ Approve",
                   command=self.on_approve).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="❌ Reject",
                   command=self.on_reject).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        self.table.refresh()

    def _selected_id(self) -> "int | None":
        return self.table.selected_id()

    # ── Actions ───────────────────────────────────────────────────────────────

    def on_view(self) -> None:
        csr_id = self._selected_id()
        if csr_id is None:
            return
        rec = get_csr_detail(csr_id, self.app.db_path)
        if rec is None:
            messagebox.showerror("Lỗi", "Không tìm thấy CSR.")
            return
        ViewCSRDialog(self, rec)

    def on_approve(self) -> None:
        csr_id = self._selected_id()
        if csr_id is None:
            return
        rec = get_csr_detail(csr_id, self.app.db_path)
        if rec is None:
            return
        if rec["status"] != "pending":
            messagebox.showwarning(
                "Không thể approve",
                f"CSR đang ở status '{rec['status']}'."
            )
            return
        ApproveCSRDialog(self, self.app, rec, on_done=self.refresh)

    def on_reject(self) -> None:
        csr_id = self._selected_id()
        if csr_id is None:
            return
        rec = get_csr_detail(csr_id, self.app.db_path)
        if rec is None:
            return
        if rec["status"] != "pending":
            messagebox.showwarning(
                "Không thể reject",
                f"CSR đang ở status '{rec['status']}'."
            )
            return
        RejectCSRDialog(self, self.app, rec, on_done=self.refresh)


# ── Dialogs ───────────────────────────────────────────────────────────────────

class ViewCSRDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, rec: dict):
        super().__init__(parent)
        self.title(f"CSR #{rec['id']} — {rec['common_name']}")
        self.geometry("760x560")
        self.transient(parent)

        info = (
            f"ID:        #{rec['id']}\n"
            f"Requester: {rec.get('requester_username') or rec['requester_id']} "
            f"(uid={rec['requester_id']}, keyId={rec['customer_key_id']})\n"
            f"Domain:    {rec['common_name']}\n"
            f"SAN:       {', '.join(rec['san_list']) or '—'}\n"
            f"Status:    {rec['status']}\n"
            f"Submit:    {rec['submitted_at']}"
        )
        if rec.get("reject_reason"):
            info += f"\nReason:    {rec['reject_reason']}"

        ttk.Label(
            self, text=info, justify=tk.LEFT,
            font=font("mono"), padding=(12, 10),
        ).pack(anchor="w")

        text = tk.Text(self, font=font("mono"), wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        pem = bytes(rec["csr_pem"]).decode("ascii", errors="replace")
        text.insert("1.0", pem)
        text.config(state=tk.DISABLED)

        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(
            btn_row, text="Copy",
            command=lambda: (self.clipboard_clear(), self.clipboard_append(pem)),
        ).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Đóng",
                   command=self.destroy).pack(side=tk.RIGHT)


class ApproveCSRDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, app, rec: dict, on_done=None):
        super().__init__(parent)
        self.app = app
        self.rec = rec
        self.on_done = on_done

        default_validity = get_int_config(
            "default_validity_days", app.db_path, 365,
        )

        frame = init_modal(self, parent=parent,
                           title=f"Approve CSR #{rec['id']}",
                           geometry="440x250")

        ttk.Label(
            frame,
            text=f"Phát hành cert cho:\n  {rec['common_name']}\n  "
                 f"(requester: {rec.get('requester_username') or rec['requester_id']})",
            justify=tk.LEFT, font=font("body"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        ttk.Label(frame, text="Hiệu lực (ngày):").grid(
            row=1, column=0, sticky="e", pady=4, padx=4,
        )
        self.validity_entry = ttk.Entry(frame, width=12)
        self.validity_entry.grid(row=1, column=1, sticky="w", pady=4, padx=4)
        self.validity_entry.insert(0, str(default_validity))

        ttk.Label(
            frame,
            text="Cert sẽ được ký bởi Root CA active hiện tại.",
            foreground="#666", font=font("caption"),
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        make_button_row(frame, submit_label="Phát hành",
                        submit_command=self.on_submit)
        self.validity_entry.focus_set()
        self.validity_entry.select_range(0, tk.END)

    def on_submit(self) -> None:
        try:
            validity = int(self.validity_entry.get().strip())
        except ValueError:
            messagebox.showerror("Lỗi", "Hiệu lực phải là số nguyên (ngày).")
            return
        try:
            issued = approve_csr(
                csr_id=self.rec["id"],
                admin_id=self.app.session["id"],
                validity_days=validity,
                db_path=self.app.db_path,
            )
        except CSRAdminError as e:
            messagebox.showerror("Approve thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.CSR_APPROVED,
            target_type="csr", target_id=str(self.rec["id"]),
            details={"issued_cert_id": issued["id"],
                     "validity_days": validity,
                     "serial_hex": issued["serial_hex"]},
        )
        write_audit(
            self.app.db_path, self.app.session["id"], Action.CERT_ISSUED,
            target_type="cert", target_id=str(issued["id"]),
            details={"serial_hex": issued["serial_hex"],
                     "common_name": issued["common_name"],
                     "owner_id": issued["owner_id"]},
        )
        messagebox.showinfo(
            "Đã phát hành",
            f"Cert #{issued['id']} (serial {issued['serial_hex']}) "
            f"hết hạn {issued['not_valid_after']}.",
        )
        if self.on_done:
            self.on_done()
        self.destroy()


class RejectCSRDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, app, rec: dict, on_done=None):
        super().__init__(parent)
        self.app = app
        self.rec = rec
        self.on_done = on_done

        frame = init_modal(self, parent=parent,
                           title=f"Reject CSR #{rec['id']}",
                           geometry="440x280")

        ttk.Label(
            frame,
            text=f"Từ chối CSR cho:\n  {rec['common_name']}\n",
            justify=tk.LEFT, font=font("body"),
        ).pack(anchor="w")

        ttk.Label(
            frame, text="Lý do từ chối (bắt buộc):",
        ).pack(anchor="w", pady=(8, 4))
        self.reason_text = tk.Text(frame, height=6, width=44, wrap=tk.WORD)
        self.reason_text.pack(fill=tk.BOTH, expand=True)

        make_button_row(frame, submit_label="Reject",
                        submit_command=self.on_submit)
        self.reason_text.focus_set()

    def on_submit(self) -> None:
        reason = self.reason_text.get("1.0", tk.END).strip()
        try:
            reject_csr(
                csr_id=self.rec["id"],
                admin_id=self.app.session["id"],
                reason=reason, db_path=self.app.db_path,
            )
        except CSRAdminError as e:
            messagebox.showerror("Reject thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.CSR_REJECTED,
            target_type="csr", target_id=str(self.rec["id"]),
            details={"reason": reason},
        )
        messagebox.showinfo("Đã từ chối", f"CSR #{self.rec['id']} đã reject.")
        if self.on_done:
            self.on_done()
        self.destroy()
