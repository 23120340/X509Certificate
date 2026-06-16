"""
ui/customer/my_certs_view.py
----------------------------
Khách hàng xem + tải chứng chỉ của mình — đáp ứng B.6.

  • Bảng cert của user (status có màu)
  • Filter status (active/expired/revoked/all)
  • View chi tiết (PEM + decoded) + Save As (download)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from ui.widgets.status_table import StatusFilterTreeFrame
from services.cert_lifecycle import list_certs_for_owner, get_cert_detail
from services.remote_csr_client import (
    list_customer_certs_from_admin_api,
    get_customer_cert_detail_from_admin_api,
    RemoteCSRClientError,
)
from ui.common import CertDetailDialog, fmt_local


STATUS_COLORS = {
    "active":  "#1e8449",
    "expired": "#888888",
    "revoked": "#c0392b",
}


class MyCertsFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app
        self.remote_api_url = getattr(app, "remote_csr_api_url", "")
        self.remote_api_token = getattr(app, "remote_csr_api_token", "")

        ttk.Label(
            self, text="Chứng nhận của tôi",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Danh sách cert đã được admin phê duyệt + phát hành cho bạn. "
                "Có thể xem chi tiết, copy PEM hoặc tải về máy."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        # Pack actions trước table để action bar không bị đẩy ra ngoài
        # viewport khi cửa sổ thấp.
        self._build_actions()
        self._build_table()
        self.refresh()

    def _build_table(self) -> None:
        self.table = StatusFilterTreeFrame(
            self,
            columns=[
                ("id",               "ID",          50),
                ("common_name",      "Domain (CN)",180),
                ("serial",           "Serial",     220),
                ("status",           "Status",      80),
                ("not_valid_before", "Hiệu lực từ",140),
                ("not_valid_after",  "Đến",        140),
            ],
            status_values=("active", "expired", "revoked", "all"),
            status_colors=STATUS_COLORS,
            default_status_index=3,
            fetch_fn=self._fetch_my_certs,
            row_mapper=self._cert_to_values,
            count_unit="cert",
        )
        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.bind_double_click(self.on_view)

    def _fetch_my_certs(self, status: str) -> list:
        if self.remote_api_url:
            password = getattr(self.app, "remote_csr_password", "")
            if not password:
                return []
            try:
                return list_customer_certs_from_admin_api(
                    api_url=self.remote_api_url,
                    username=self.app.session["username"],
                    password=password,
                    status=None if status == "all" else status,
                    token=self.remote_api_token,
                )
            except RemoteCSRClientError as e:
                messagebox.showerror("Không tải được cert từ Admin", str(e))
                return []
        return list_certs_for_owner(
            self.app.session["id"], self.app.db_path,
            status=None if status == "all" else status,
        )

    def _cert_to_values(self, c: dict) -> tuple:
        serial_str = c["serial_hex"][:32] + ("…" if len(c["serial_hex"]) > 32 else "")
        return (
            c["id"], c["common_name"], serial_str, c["status"],
            fmt_local(c["not_valid_before"]),
            fmt_local(c["not_valid_after"]),
        )

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(8, 0))
        ttk.Button(bar, text="📋 Xem chi tiết",
                   command=self.on_view).pack(side=tk.LEFT)
        ttk.Button(bar, text="💾 Tải về (Save as)",
                   command=self.on_download).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        self.table.refresh()

    def _selected_id(self) -> "int | None":
        return self.table.selected_id()

    def on_view(self) -> None:
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = self._get_cert_detail(cert_id)
        if rec is None:
            messagebox.showerror("Lỗi", "Không tìm thấy cert.")
            return
        CertDetailDialog(self, rec)

    def on_download(self) -> None:
        from tkinter import filedialog
        cert_id = self._selected_id()
        if cert_id is None:
            return
        rec = self._get_cert_detail(cert_id)
        if rec is None:
            return
        default_name = (
            f"{rec['common_name']}-{rec['serial_hex'][:8]}.crt"
        )
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Lưu cert PEM",
            defaultextension=".crt",
            initialfile=default_name,
            filetypes=(("PEM cert", "*.crt *.pem"), ("All files", "*.*")),
        )
        if not path:
            return
        with open(path, "wb") as f:
            pem = rec["cert_pem"]
            f.write(pem.encode("ascii") if isinstance(pem, str) else bytes(pem))
        messagebox.showinfo("Đã lưu", f"Đã lưu cert vào:\n{path}")

    def _get_cert_detail(self, cert_id: int) -> "dict | None":
        if not self.remote_api_url:
            return get_cert_detail(cert_id, self.app.db_path,
                                   owner_id=self.app.session["id"])
        password = getattr(self.app, "remote_csr_password", "")
        if not password:
            messagebox.showerror(
                "Thiếu mật khẩu",
                "Vào mục Yêu cầu cấp cert, nhập mật khẩu customer trên Admin rồi Refresh.",
            )
            return None
        try:
            rec = get_customer_cert_detail_from_admin_api(
                api_url=self.remote_api_url,
                username=self.app.session["username"],
                password=password,
                cert_id=cert_id,
                token=self.remote_api_token,
            )
        except RemoteCSRClientError as e:
            messagebox.showerror("Không tải được cert từ Admin", str(e))
            return None
        if isinstance(rec.get("cert_pem"), str):
            rec["cert_pem"] = rec["cert_pem"].encode("ascii")
        return rec
