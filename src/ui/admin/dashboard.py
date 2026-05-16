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

from ui.common import build_dashboard_header, coming_soon_frame
from ui.theme import COLOR, SPACE, font
from ui.admin.audit_view import AuditLogFrame
from ui.admin.system_config_view import SystemConfigFrame
from ui.admin.root_ca_view import RootCAFrame
from ui.admin.csr_queue_view import CSRQueueFrame
from ui.admin.cert_mgmt_view import CertMgmtFrame
from ui.admin.revoke_queue_view import RevokeQueueFrame
from ui.admin.crl_publish_view import CRLPublishFrame


class AdminDashboardFrame(ttk.Frame):
    """Frame chính cho admin role."""

    # Cấu hình menu: (label, milestone, factory)
    # factory(parent, app) → ttk.Frame để render trong content area
    MENU: "list[tuple[str, str, str]]" = [
        ("Tổng quan",                 "ready", "overview"),
        ("Cấu hình hệ thống (A.3)",   "ready", "system_config"),
        ("Root CA (A.4-5)",           "ready", "root_ca"),
        ("Duyệt CSR (A.6-7)",         "ready", "csr_queue"),
        ("Quản lý chứng nhận (A.8)",  "ready", "cert_mgmt"),
        ("Duyệt thu hồi (A.9)",       "ready", "revoke_queue"),
        ("Cập nhật CRL (A.10)",       "ready", "crl_publish"),
        ("Audit log (A.11)",          "ready", "audit_log"),
        ("Verification Lab",          "ready", "verify_lab"),
    ]

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent)
        self.app = app

        build_dashboard_header(self, app, role_label="ADMIN")

        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_content_area(body)
        self._show_page("overview")

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

    # ── Pages ─────────────────────────────────────────────────────────────────

    def _page_overview(self, parent: tk.Misc, app) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=SPACE["xl"])
        ttk.Label(
            frame, text=f"Xin chào, {app.session['username']}",
            style="Display.TLabel",
        ).pack(anchor="w", pady=(0, SPACE["xs"]))
        ttk.Label(
            frame,
            text="Trung tâm quản trị Certificate Authority",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, SPACE["lg"]))
        ttk.Label(
            frame,
            text=(
                "Chọn một mục từ menu bên trái để bắt đầu.\n\n"
                "11 chức năng quản trị (A.1-A.11) đã sẵn sàng:\n"
                "  • Cấu hình hệ thống + sinh Root CA (A.3–A.5)\n"
                "  • Duyệt CSR + phát hành cert (A.6–A.7)\n"
                "  • Quản lý cert: revoke / renew (A.8)\n"
                "  • Duyệt yêu cầu thu hồi (A.9)\n"
                "  • Publish CRL (A.10)\n"
                "  • Audit log (A.11)\n\n"
                "Verification Lab cung cấp 5-bước verify + lifecycle demo "
                "để minh họa cách client xác thực cert."
            ),
            justify=tk.LEFT,
            style="TLabel",
            wraplength=720,
        ).pack(anchor="w")
        return frame

    def _page_verify_lab(self, parent: tk.Misc, app) -> ttk.Frame:
        """Launcher cho legacy lifecycle demo (mở Toplevel)."""
        frame = ttk.Frame(parent, padding=24)
        ttk.Label(
            frame, text="Verification Lab",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text=(
                "Phòng thí nghiệm xác thực cert: tạo nhiều socket server với "
                "các 'flavor' khác nhau (valid / expired / revoked / tampered / "
                "renew rotate), chạy 5 bước verify để minh họa cách client phát "
                "hiện từng loại lỗi.\n\n"
                "Đây là demo gốc của hệ thống, giữ lại để giảng giải mô hình "
                "Root CA + Trust Store + CRL/OCSP. Tính năng upload cert ngoài "
                "(B.9) sẽ tái dùng đúng module verify này."
            ),
            justify=tk.LEFT,
            foreground="#444",
            wraplength=720,
        ).pack(anchor="w", pady=(8, 12))

        ttk.Button(
            frame, text="Mở Verification Lab (Toplevel)",
            command=self._open_verify_lab,
        ).pack(anchor="w")
        return frame

    def _open_verify_lab(self) -> None:
        from legacy.lifecycle_demo import launch_as_toplevel
        launch_as_toplevel(self.app.root)
