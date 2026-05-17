"""
ui/customer/dashboard.py
------------------------
Customer dashboard — sidebar menu theo nhóm chức năng B.1-9.

Hiện tại chỉ có Đổi mật khẩu (B.3, qua header) và Tổng quan là sẵn sàng.
Các tính năng khác hiển thị placeholder "Coming in M…".
"""

import tkinter as tk
from tkinter import ttk

from ui.common import build_dashboard_header, coming_soon_frame, hero_section
from ui.theme import COLOR, SPACE, font
from ui.customer.my_keys_view import MyKeysFrame
from ui.customer.csr_submit_view import CSRSubmitFrame
from ui.customer.my_certs_view import MyCertsFrame
from ui.customer.revoke_request_view import RevokeRequestFrame
from ui.customer.view_crl_view import ViewCRLFrame
from ui.customer.upload_external_view import UploadExternalFrame


class CustomerDashboardFrame(ttk.Frame):

    MENU: "list[tuple[str, str, str]]" = [
        ("Tổng quan",                    "ready", "overview"),
        ("Keypair của tôi",              "ready", "my_keys"),
        ("Yêu cầu cấp cert",             "ready", "my_csr"),
        ("Chứng nhận của tôi",           "ready", "my_certs"),
        ("Yêu cầu thu hồi",              "ready", "revoke_request"),
        ("Tra cứu CRL",                  "ready", "view_crl"),
        ("Upload cert ngoài",            "ready", "external_upload"),
    ]

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent)
        self.app = app

        build_dashboard_header(self, app, role_label="CUSTOMER")

        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_content_area(body)
        self._show_page("overview")

    def _build_sidebar(self, parent: ttk.Frame) -> None:
        sidebar = ttk.Frame(parent, padding=SPACE["sm"], style="Sidebar.TFrame")
        sidebar.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(
            sidebar, text="MENU",
            style="Sidebar.TLabel",
            foreground=COLOR["text_subtle"],
            font=font("caption"),
        ).pack(anchor="w", pady=(SPACE["xs"], SPACE["sm"]),
               padx=SPACE["sm"])

        for label, milestone, key in self.MENU:
            text = label if milestone == "ready" else f"{label}  •{milestone}"
            ttk.Button(
                sidebar, text=text, width=28,
                style="Ghost.TButton",
                command=lambda k=key: self._show_page(k),
            ).pack(pady=SPACE["xxs"], fill=tk.X)

        ttk.Separator(parent, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y)

    def _build_content_area(self, parent: ttk.Frame) -> None:
        self.content = ttk.Frame(parent)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _show_page(self, key: str) -> None:
        for child in self.content.winfo_children():
            child.destroy()

        factory = {
            "overview":         self._page_overview,
            "my_keys":          lambda p, a: MyKeysFrame(p, a),
            "my_csr":           lambda p, a: CSRSubmitFrame(p, a),
            "my_certs":         lambda p, a: MyCertsFrame(p, a),
            "revoke_request":   lambda p, a: RevokeRequestFrame(p, a),
            "view_crl":         lambda p, a: ViewCRLFrame(p, a),
            "external_upload":  lambda p, a: UploadExternalFrame(p, a),
        }.get(key, self._page_overview)

        factory(self.content, self.app).pack(fill=tk.BOTH, expand=True)

    def _page_overview(self, parent: tk.Misc, app) -> ttk.Frame:
        return hero_section(
            parent,
            eyebrow="Customer Portal",
            title=f"Xin chào, {app.session['username']}",
            subtitle="Cổng khách hàng — Xin cấp Chứng nhận X.509 cho domain của bạn.",
            description=(
                "Quy trình điển hình: sinh keypair RSA → submit CSR → đợi Admin "
                "duyệt → tải cert PEM về máy. Khi cần, có thể gửi yêu cầu thu "
                "hồi hoặc tra cứu CRL công khai."
            ),
            primary_cta=("Sinh keypair",
                         lambda: self._show_page("my_keys")),
            secondary_cta=("Submit CSR",
                           lambda: self._show_page("my_csr")),
            features=[
                ("◆", "Keypair của tôi",
                 "Sinh RSA private/public key, lưu mã hóa trong DB cục bộ."),
                ("▣", "Submit CSR",
                 "Tạo yêu cầu cấp cert cho domain bạn sở hữu."),
                ("◉", "Cert của tôi",
                 "Xem & tải cert PEM về máy khi Admin đã duyệt."),
                ("▶", "Yêu cầu thu hồi",
                 "Gửi yêu cầu thu hồi cert khi key bị lộ hoặc hết dùng."),
                ("⬢", "Tra cứu CRL",
                 "Xem danh sách thu hồi công khai của CA."),
                ("✦", "Verify cert ngoài",
                 "Upload cert bất kỳ + chạy 5 bước verify đầy đủ."),
            ],
        )
