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

        self._build_toolbar()
        self._build_tree()
        self._build_actions()
        self.refresh()

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(bar, text="Filter status:").pack(side=tk.LEFT, padx=(0, 4))
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
        cols = ("id", "requester", "common_name", "san", "status",
                "submitted_at", "reviewed_at")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        labels = {
            "id": "ID", "requester": "Requester",
            "common_name": "Domain (CN)", "san": "SAN",
            "status": "Status",
            "submitted_at": "Submit", "reviewed_at": "Reviewed",
        }
        widths = {"id": 50, "requester": 110, "common_name": 180,
                  "san": 220, "status": 80,
                  "submitted_at": 140, "reviewed_at": 140}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        vsb.place(in_=self.tree, relx=1.0, x=-1, rely=0, relheight=1.0, anchor="ne")

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
        items = list_all_csr(
            self.app.db_path,
            status=None if status == "all" else status,
        )
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for c in items:
            san_str = ", ".join(c["san_list"]) if c["san_list"] else "—"
            self.tree.insert(
                "", tk.END, iid=str(c["id"]),
                values=(
                    c["id"],
                    c.get("requester_username") or f"uid={c['requester_id']}",
                    c["common_name"], san_str, c["status"],
                    c["submitted_at"][:19].replace("T", " "),
                    (c["reviewed_at"] or "—")[:19].replace("T", " ") if c.get("reviewed_at") else "—",
                ),
                tags=(c["status"],),
            )
        self.count_label.config(text=f"{len(items)} CSR")

    def _selected_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn",
                                    "Hãy chọn CSR trong bảng.")
            return None
        return int(sel[0])

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

        self.title(f"Approve CSR #{rec['id']}")
        self.geometry("440x250")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        default_validity = get_int_config(
            "default_validity_days", app.db_path, 365,
        )

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

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

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=99, column=0, columnspan=2, pady=(16, 0), sticky="e")
        ttk.Button(btn_row, text="Phát hành",
                   command=self.on_submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text="Hủy",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)
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

        self.title(f"Reject CSR #{rec['id']}")
        self.geometry("440x280")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

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

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X, pady=(12, 0))
        ttk.Button(btn_row, text="Reject",
                   command=self.on_submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text="Hủy",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)
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
