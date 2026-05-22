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

from ui.theme import font
from ui.widgets.status_table import StatusFilterTreeFrame
from ui.widgets.modal import init_modal, make_button_row
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
            self, text="Quản lý chứng nhận",
            font=font("heading_lg"),
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

        # Pack actions trước table — table fill=BOTH+expand=True sẽ chiếm
        # toàn bộ không gian còn lại; nếu pack ngược, action bar bị đẩy
        # ra ngoài viewport ở cửa sổ thấp.
        self._build_actions()
        self._build_table()
        self.refresh()

    def _build_table(self) -> None:
        self.table = StatusFilterTreeFrame(
            self,
            columns=[
                ("id",              "ID",          50),
                ("owner",           "Owner",      100),
                ("common_name",     "Domain (CN)",160),
                ("serial",          "Serial",     180),
                ("status",          "Status",      80),
                ("not_valid_after", "Hết hạn",    140),
                ("renewed_from",    "Renew từ",    80),
            ],
            status_values=("active", "expired", "revoked", "all"),
            status_colors=STATUS_COLORS,
            default_status_index=3,  # "all"
            fetch_fn=self._fetch_certs,
            row_mapper=self._cert_to_values,
            count_unit="cert",
        )
        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.bind_double_click(self.on_view)

    def _fetch_certs(self, status: str) -> list:
        return list_all_certs(
            self.app.db_path,
            status=None if status == "all" else status,
        )

    def _cert_to_values(self, c: dict) -> tuple:
        serial_str = c["serial_hex"][:32] + ("…" if len(c["serial_hex"]) > 32 else "")
        return (
            c["id"],
            c.get("owner_username") or f"uid={c['owner_id']}",
            c["common_name"], serial_str, c["status"],
            c["not_valid_after"][:19].replace("T", " "),
            c["renewed_from_id"] or "—",
        )

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(8, 0))
        ttk.Button(bar, text="📋 Xem chi tiết",
                   command=self.on_view).pack(side=tk.LEFT)
        ttk.Button(bar, text="🔄 Renew",
                   command=self.on_renew).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="🚫 Revoke",
                   command=self.on_revoke).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        self.table.refresh()

    def _selected_id(self) -> "int | None":
        return self.table.selected_id()

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

        frame = init_modal(self, parent=parent,
                           title=f"Revoke cert #{rec['id']}",
                           geometry="440x300")

        ttk.Label(
            frame,
            text=f"Thu hồi cert cho:\n  {rec['common_name']} (serial {rec['serial_hex'][:16]}…)\n",
            justify=tk.LEFT, font=font("body"),
        ).pack(anchor="w")

        ttk.Label(
            frame, text="Lý do thu hồi (bắt buộc):",
        ).pack(anchor="w", pady=(8, 4))
        self.reason_text = tk.Text(frame, height=6, width=44, wrap=tk.WORD)
        self.reason_text.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="CRL/OCSP DB sẽ snapshot trạng thái này khi admin Publish CRL ở M8.",
            foreground="#888", font=font("caption"),
        ).pack(anchor="w", pady=(6, 0))

        make_button_row(frame, submit_label="Revoke",
                        submit_command=self.on_submit)
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

        default_validity = get_int_config(
            "default_validity_days", app.db_path, 365,
        )

        frame = init_modal(self, parent=parent,
                           title=f"Renew cert #{rec['id']}",
                           geometry="460x280")

        ttk.Label(
            frame,
            text=(
                f"Phát hành cert mới cho:\n"
                f"  {rec['common_name']}\n"
                f"  serial cũ: {rec['serial_hex'][:24]}…\n"
                f"  hết hạn cũ: {rec['not_valid_after'][:19].replace('T', ' ')}"
            ),
            justify=tk.LEFT, font=font("body"),
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
            foreground="#666", font=font("caption"), wraplength=400,
            justify=tk.LEFT,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        make_button_row(frame, submit_label="Renew",
                        submit_command=self.on_submit)
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
