"""
ui/admin/cert_mgmt_view.py
--------------------------
Quản lý các chứng nhận đã cấp phát — đáp ứng A.8 (revoke + renew).

  • Bảng tất cả cert (status có màu): active / expired / revoked
  • Filter status
  • Actions: Xem chi tiết (CertDetailDialog), Revoke (reason bắt buộc),
    Renew (validity_days), Refresh
"""

import tkinter as tk
from tkinter import ttk, messagebox

from services.audit import write_audit, Action
from services.cert_lifecycle import (
    list_all_certs, get_cert_detail, revoke_cert, renew_cert,
    CertLifecycleError,
)
from services.system_config import get_int_config
from ui.common import CertDetailDialog


STATUS_COLORS = {
    "active":  "#1e8449",
    "expired": "#888888",
    "revoked": "#c0392b",
}


class CertMgmtFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Quản lý chứng nhận (A.8)",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Danh sách tất cả cert đã phát hành. Có thể thu hồi (revoke "
                "với reason) hoặc gia hạn (renew — phát hành cert mới cùng "
                "subject + public key, validity mới)."
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
        self.status_combo.current(3)  # "all" mặc định
        self.status_combo.pack(side=tk.LEFT)
        self.status_combo.bind("<<ComboboxSelected>>",
                               lambda e: self.refresh())
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))
        self.count_label = ttk.Label(bar, text="", foreground="#666")
        self.count_label.pack(side=tk.RIGHT)

    def _build_tree(self) -> None:
        cols = ("id", "owner", "common_name", "serial",
                "status", "not_valid_after", "renewed_from")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        labels = {
            "id": "ID", "owner": "Owner",
            "common_name": "Domain (CN)", "serial": "Serial",
            "status": "Status",
            "not_valid_after": "Hết hạn",
            "renewed_from": "Renew từ",
        }
        widths = {"id": 50, "owner": 100, "common_name": 160,
                  "serial": 180, "status": 80,
                  "not_valid_after": 140, "renewed_from": 80}
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
        ttk.Button(bar, text="🔄 Renew",
                   command=self.on_renew).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="🚫 Revoke",
                   command=self.on_revoke).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        status = self.status_combo.get()
        items = list_all_certs(
            self.app.db_path,
            status=None if status == "all" else status,
        )
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for c in items:
            self.tree.insert(
                "", tk.END, iid=str(c["id"]),
                values=(
                    c["id"],
                    c.get("owner_username") or f"uid={c['owner_id']}",
                    c["common_name"],
                    c["serial_hex"][:32] + ("…" if len(c["serial_hex"]) > 32 else ""),
                    c["status"],
                    c["not_valid_after"][:19].replace("T", " "),
                    c["renewed_from_id"] or "—",
                ),
                tags=(c["status"],),
            )
        self.count_label.config(text=f"{len(items)} cert")

    def _selected_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn",
                                    "Hãy chọn cert trong bảng.")
            return None
        return int(sel[0])

    # ── Actions ───────────────────────────────────────────────────────────────

    def on_view(self) -> None:
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = get_cert_detail(cert_id, self.app.db_path)
        if rec is None:
            return
        CertDetailDialog(self, rec)

    def on_revoke(self) -> None:
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = get_cert_detail(cert_id, self.app.db_path)
        if rec is None:
            return
        if rec["status"] == "revoked":
            messagebox.showwarning(
                "Đã revoked",
                f"Cert #{cert_id} đã thu hồi lúc {rec['revoked_at']}.",
            )
            return
        RevokeCertDialog(self, self.app, rec, on_done=self.refresh)

    def on_renew(self) -> None:
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = get_cert_detail(cert_id, self.app.db_path)
        if rec is None:
            return
        if rec["status"] == "revoked":
            messagebox.showwarning(
                "Không thể renew",
                "Cert đã thu hồi — phát hành cert mới qua CSR.",
            )
            return
        RenewCertDialog(self, self.app, rec, on_done=self.refresh)


# ── Dialogs ───────────────────────────────────────────────────────────────────

class RevokeCertDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, app, rec: dict, on_done=None):
        super().__init__(parent)
        self.app = app
        self.rec = rec
        self.on_done = on_done

        self.title(f"Revoke cert #{rec['id']}")
        self.geometry("440x300")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=f"Thu hồi cert cho:\n  {rec['common_name']} (serial {rec['serial_hex'][:16]}…)\n",
            justify=tk.LEFT, font=("Segoe UI", 10),
        ).pack(anchor="w")

        ttk.Label(
            frame, text="Lý do thu hồi (bắt buộc):",
        ).pack(anchor="w", pady=(8, 4))
        self.reason_text = tk.Text(frame, height=6, width=44, wrap=tk.WORD)
        self.reason_text.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="CRL/OCSP DB sẽ snapshot trạng thái này khi admin Publish CRL ở M8.",
            foreground="#888", font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(6, 0))

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_row, text="Revoke",
                   command=self.on_submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text="Hủy",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)
        self.reason_text.focus_set()

    def on_submit(self) -> None:
        reason = self.reason_text.get("1.0", tk.END).strip()
        try:
            revoked = revoke_cert(
                self.rec["id"], self.app.session["id"], reason,
                self.app.db_path,
            )
        except CertLifecycleError as e:
            messagebox.showerror("Revoke thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.CERT_REVOKED,
            target_type="cert", target_id=str(self.rec["id"]),
            details={
                "serial_hex": self.rec["serial_hex"],
                "common_name": self.rec["common_name"],
                "reason": reason,
            },
        )
        messagebox.showinfo("Đã revoke",
                            f"Cert #{self.rec['id']} đã thu hồi.")
        if self.on_done:
            self.on_done()
        self.destroy()


class RenewCertDialog(tk.Toplevel):

    def __init__(self, parent: tk.Misc, app, rec: dict, on_done=None):
        super().__init__(parent)
        self.app = app
        self.rec = rec
        self.on_done = on_done

        self.title(f"Renew cert #{rec['id']}")
        self.geometry("460x280")
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
            text=(
                f"Phát hành cert mới cho:\n"
                f"  {rec['common_name']}\n"
                f"  serial cũ: {rec['serial_hex'][:24]}…\n"
                f"  hết hạn cũ: {rec['not_valid_after'][:19].replace('T', ' ')}"
            ),
            justify=tk.LEFT, font=("Segoe UI", 10),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        ttk.Label(frame, text="Hiệu lực mới (ngày):").grid(
            row=1, column=0, sticky="e", pady=4, padx=4,
        )
        self.validity_entry = ttk.Entry(frame, width=12)
        self.validity_entry.grid(row=1, column=1, sticky="w", pady=4, padx=4)
        self.validity_entry.insert(0, str(default_validity))

        ttk.Label(
            frame,
            text=(
                "Cert mới giữ nguyên public key của customer (không cần "
                "submit CSR mới). Cert cũ KHÔNG tự revoke."
            ),
            foreground="#666", font=("Segoe UI", 8), wraplength=400,
            justify=tk.LEFT,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=99, column=0, columnspan=2, pady=(16, 0), sticky="e")
        ttk.Button(btn_row, text="Renew",
                   command=self.on_submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text="Hủy",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)
        self.validity_entry.focus_set()
        self.validity_entry.select_range(0, tk.END)

    def on_submit(self) -> None:
        try:
            validity = int(self.validity_entry.get().strip())
        except ValueError:
            messagebox.showerror("Lỗi", "Validity phải là số nguyên (ngày).")
            return
        try:
            new_cert = renew_cert(
                self.rec["id"], self.app.session["id"], validity,
                self.app.db_path,
            )
        except CertLifecycleError as e:
            messagebox.showerror("Renew thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.CERT_RENEWED,
            target_type="cert", target_id=str(new_cert["id"]),
            details={
                "from_cert_id": self.rec["id"],
                "new_serial_hex": new_cert["serial_hex"],
                "common_name": new_cert["common_name"],
                "validity_days": validity,
            },
        )
        messagebox.showinfo(
            "Đã renew",
            f"Cert mới #{new_cert['id']} (serial {new_cert['serial_hex'][:16]}…) "
            f"hết hạn {new_cert['not_valid_after'][:19].replace('T', ' ')}.",
        )
        if self.on_done:
            self.on_done()
        self.destroy()
