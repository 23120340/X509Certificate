"""
ui/admin/dashboard.py
---------------------
Admin dashboard — sidebar menu theo nhóm chức năng A.1-11.

  • Header bar (build_dashboard_header): role label + Đổi mật khẩu + Đăng xuất
  • Sidebar: 8 menu item (A.2 đã ở header → bỏ; còn A.3 → A.11 + Lab)
  • Content area: render frame ứng với mục được chọn

Hiện tại các mục A.3 → A.10 hiển thị placeholder "Coming in M…".
Mục A.11 (Audit log) và Verification Lab đã wire-up hoàn chỉnh.
"""

import tkinter as tk
from tkinter import ttk

from ui.common import build_dashboard_header, coming_soon_frame, hero_section
from ui.theme import COLOR, SPACE, font
from ui.admin.audit_view import AuditLogFrame
from ui.admin.system_config_view import SystemConfigFrame
from ui.admin.root_ca_view import RootCAFrame
from ui.admin.csr_queue_view import CSRQueueFrame
from ui.admin.cert_mgmt_view import CertMgmtFrame
from ui.admin.revoke_queue_view import RevokeQueueFrame
from ui.admin.crl_publish_view import CRLPublishFrame
from services.infra_manager import (
    get_infra, PROD_CRL_PORT, PROD_OCSP_PORT, LAB_CRL_PORT, LAB_OCSP_PORT,
)


class AdminDashboardFrame(ttk.Frame):
    """Frame chính cho admin role."""

    # Cấu hình menu: (label, milestone, factory)
    # factory(parent, app) → ttk.Frame để render trong content area
    MENU: "list[tuple[str, str, str]]" = [
        ("Tổng quan",                 "ready", "overview"),
        ("Cấu hình hệ thống",         "ready", "system_config"),
        ("Root CA",                   "ready", "root_ca"),
        ("Duyệt CSR",                 "ready", "csr_queue"),
        ("Quản lý chứng nhận",        "ready", "cert_mgmt"),
        ("Duyệt thu hồi",             "ready", "revoke_queue"),
        ("Cập nhật CRL",              "ready", "crl_publish"),
        ("Audit log",                 "ready", "audit_log"),
        ("Verification Lab",          "ready", "verify_lab"),
    ]

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent)
        self.app = app

        build_dashboard_header(self, app, role_label="ADMIN")
        self._build_infra_status_bar()

        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_content_area(body)
        self._show_page("overview")

    # ── Infra status bar ─────────────────────────────────────────────────────

    def _build_infra_status_bar(self) -> None:
        """Badge hiển thị trạng thái Prod + Lab CRL/OCSP servers.

        Refresh sau mỗi page-switch (poll thủ công đủ — server state ít đổi).
        """
        bar = ttk.Frame(
            self, padding=(SPACE["lg"], SPACE["xs"]),
            style="Surface.TFrame",
        )
        bar.pack(fill=tk.X)

        self._status_badges: "list[ttk.Label]" = []
        for label_text in ("Prod CRL", "Prod OCSP", "Lab CRL", "Lab OCSP"):
            badge = ttk.Label(
                bar, text=f"  {label_text}: …  ",
                style="Surface.TLabel",
                font=font("caption"),
                padding=(SPACE["xs"], SPACE["xxs"]),
            )
            badge.pack(side=tk.LEFT, padx=(0, SPACE["xs"]))
            self._status_badges.append(badge)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)
        self._refresh_status_badges()

    def _refresh_status_badges(self) -> None:
        """Đọc InfraManager state → đổ vào badge labels."""
        st = get_infra().status()
        ports = [PROD_CRL_PORT, PROD_OCSP_PORT, LAB_CRL_PORT, LAB_OCSP_PORT]
        flags = [st["prod_crl"], st["prod_ocsp"], st["lab_crl"], st["lab_ocsp"]]
        names = ["Prod CRL", "Prod OCSP", "Lab CRL", "Lab OCSP"]

        for badge, name, port, on in zip(self._status_badges, names, ports, flags):
            mark = "ON" if on else "OFF"
            color = COLOR.get("success", "#16a34a") if on \
                else COLOR.get("text_subtle", "#888")
            badge.configure(
                text=f"  {name}: {mark} :{port}  ",
                foreground=color,
            )

    # ── Sidebar ───────────────────────────────────────────────────────────────

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
            text = label
            if milestone != "ready":
                text = f"{label}  •{milestone}"
            ttk.Button(
                sidebar, text=text, width=28,
                style="Ghost.TButton",
                command=lambda k=key: self._show_page(k),
            ).pack(pady=SPACE["xxs"], fill=tk.X)

        ttk.Separator(parent, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y)

    # ── Content area ──────────────────────────────────────────────────────────

    def _build_content_area(self, parent: ttk.Frame) -> None:
        self.content = ttk.Frame(parent)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _show_page(self, key: str) -> None:
        for child in self.content.winfo_children():
            child.destroy()

        factory = {
            "overview":       self._page_overview,
            "audit_log":      lambda p, a: AuditLogFrame(p, a),
            "verify_lab":     self._page_verify_lab,
            "system_config":  lambda p, a: SystemConfigFrame(p, a),
            "root_ca":        lambda p, a: RootCAFrame(p, a),
            "csr_queue":      lambda p, a: CSRQueueFrame(p, a),
            "cert_mgmt":      lambda p, a: CertMgmtFrame(p, a),
            "revoke_queue":   lambda p, a: RevokeQueueFrame(p, a),
            "crl_publish":    lambda p, a: CRLPublishFrame(p, a),
        }.get(key, self._page_overview)

        factory(self.content, self.app).pack(fill=tk.BOTH, expand=True)
        # Refresh badge — Lab servers có thể vừa start/stop khi user mở Lab
        self._refresh_status_badges()

    # ── Pages ─────────────────────────────────────────────────────────────────

    def _page_overview(self, parent: tk.Misc, app) -> ttk.Frame:
        return hero_section(
            parent,
            eyebrow="Admin Portal",
            title=f"Xin chào, {app.session['username']}",
            subtitle="Trung tâm quản trị Certificate Authority — đủ chức năng vận hành end-to-end.",
            description=(
                "Chọn một mục từ menu bên trái để bắt đầu, hoặc mở thẳng "
                "Verification Lab để minh họa cách client xác thực cert "
                "thật trên 5 bước chuẩn X.509."
            ),
            primary_cta=("Mở Verification Lab", self._open_verify_lab),
            secondary_cta=("Xem Audit log", lambda: self._show_page("audit_log")),
            features=[
                ("◆", "Cấu hình & Root CA",
                 "Khởi tạo policy, sinh Root CA self-signed lưu encrypted."),
                ("▣", "Duyệt CSR",
                 "Pipeline review CSR, phát hành cert ký bởi Root CA."),
                ("◉", "Lifecycle cert",
                 "Quản lý cert đã phát hành: tra cứu, revoke, renew."),
                ("▶", "Duyệt thu hồi",
                 "Xét yêu cầu thu hồi từ customer, cập nhật CRL nội bộ."),
                ("⬢", "CRL & OCSP",
                 "Publish CRL định kỳ + OCSP responder thời gian thực."),
                ("✦", "Audit log",
                 "Trail đầy đủ mọi action của admin và customer."),
            ],
        )

    def _page_verify_lab(self, parent: tk.Misc, app) -> ttk.Frame:
        """Launcher cho legacy lifecycle demo (mở Toplevel)."""
        return hero_section(
            parent,
            eyebrow="Laboratory",
            title="Verification Lab",
            subtitle=(
                "Phòng thí nghiệm xác thực cert — 5 bước verify trên cert "
                "thật, với các flavor lỗi để minh họa từng nhánh thất bại."
            ),
            description=(
                "Lab tạo nhiều socket server với các flavor: valid / expired / "
                "revoked / tampered / renew rotate. Client chạy 5 bước verify "
                "qua TLS thật để cho thấy từng loại lỗi bị phát hiện ở bước "
                "nào. Đây là demo gốc giữ lại để giảng giải mô hình Root CA + "
                "Trust Store + CRL/OCSP — module verify này được tái dùng cho "
                "tính năng upload cert ngoài của customer."
            ),
            primary_cta=("Mở Verification Lab", self._open_verify_lab),
            features=[
                ("1", "Parse PEM",
                 "Đọc & validate format X.509 của cert nhận từ server."),
                ("2", "Chain build",
                 "Dựng chain từ leaf tới Root CA trong trust store."),
                ("3", "Signature verify",
                 "Verify RSA signature dọc theo chain bằng public key cha."),
                ("4", "Validity window",
                 "Kiểm tra notBefore/notAfter, chấp nhận clock skew nhỏ."),
                ("5", "Revocation check",
                 "Tra CRL + OCSP cho status hiện tại của cert leaf."),
            ],
            cols=3,
        )

    def _open_verify_lab(self) -> None:
        from legacy.lifecycle_demo import launch_as_toplevel
        launch_as_toplevel(self.app.root)
