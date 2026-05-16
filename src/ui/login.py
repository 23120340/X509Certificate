"""
ui/login.py
-----------
Màn hình Đăng nhập + Đăng ký (customer-only).

Admin được seed ở bootstrap; user mới đăng ký qua UI là customer.
Sau login thành công → gọi `app.on_login_success(user)` để route tới dashboard.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from services.auth import login, register_user, AuthError
from services.audit import write_audit, Action
from ui.theme import COLOR, SPACE, font


class LoginFrame(ttk.Frame):
    """Frame chứa form login + form register, switch qua notebook tab."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        self._build_header()
        self._build_notebook()

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        title = ttk.Label(
            self, text="X.509 CA Management",
            style="Display.TLabel",
        )
        title.pack(pady=(0, SPACE["xs"]))

        subtitle = ttk.Label(
            self,
            text="Hệ thống quản lý và cấp phát chứng nhận số theo tiêu chuẩn X.509",
            style="Muted.TLabel",
        )
        subtitle.pack(pady=(0, SPACE["lg"]))

    def _build_notebook(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        nb.add(self._build_login_tab(nb),    text="Đăng nhập")
        nb.add(self._build_register_tab(nb), text="Đăng ký (Customer)")

    # ── Login tab ─────────────────────────────────────────────────────────────

    def _build_login_tab(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=16)

        ttk.Label(frame, text="Username:").grid(
            row=0, column=0, sticky="e", pady=6, padx=4
        )
        self.login_username = ttk.Entry(frame, width=28)
        self.login_username.grid(row=0, column=1, pady=6, padx=4, sticky="ew")

        ttk.Label(frame, text="Password:").grid(
            row=1, column=0, sticky="e", pady=6, padx=4
        )
        self.login_password = ttk.Entry(frame, width=28, show="•")
        self.login_password.grid(row=1, column=1, pady=6, padx=4, sticky="ew")

        btn = ttk.Button(frame, text="Đăng nhập",
                         style="Primary.TButton", command=self.on_login)
        btn.grid(row=2, column=0, columnspan=2, pady=(SPACE["md"], SPACE["xs"]),
                 sticky="ew")

        # Enter để submit
        for w in (self.login_username, self.login_password):
            w.bind("<Return>", lambda e: self.on_login())

        # Hint admin mặc định (chỉ hiển thị nếu user chưa đổi)
        hint = ttk.Label(
            frame,
            text="Mặc định lần đầu: admin / Admin@123 — ĐỔI ngay sau khi đăng nhập.",
            style="Subtle.TLabel",
        )
        hint.grid(row=3, column=0, columnspan=2, pady=(SPACE["sm"], 0))

        frame.columnconfigure(1, weight=1)
        self.login_username.focus_set()
        return frame

    def on_login(self) -> None:
        username = self.login_username.get().strip()
        password = self.login_password.get()
        try:
            user = login(username, password, self.app.db_path)
        except AuthError as e:
            write_audit(
                self.app.db_path, None, Action.LOGIN_FAILED,
                target_type="user", target_id=username or None,
            )
            messagebox.showerror("Đăng nhập thất bại", str(e))
            self.login_password.delete(0, tk.END)
            return
        self.app.on_login_success(user)

    # ── Register tab (customer only) ──────────────────────────────────────────

    def _build_register_tab(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=16)

        info = ttk.Label(
            frame,
            text=(
                "Đăng ký tài khoản Customer để xin cấp Chứng nhận X.509.\n"
                "Tài khoản Admin do hệ thống cấp phát, không tự đăng ký."
            ),
            justify=tk.LEFT,
            style="Muted.TLabel",
        )
        info.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="e", pady=6, padx=4)
        self.reg_username = ttk.Entry(frame, width=28)
        self.reg_username.grid(row=1, column=1, pady=6, padx=4, sticky="ew")

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="e", pady=6, padx=4)
        self.reg_password = ttk.Entry(frame, width=28, show="•")
        self.reg_password.grid(row=2, column=1, pady=6, padx=4, sticky="ew")

        ttk.Label(frame, text="Xác nhận:").grid(row=3, column=0, sticky="e", pady=6, padx=4)
        self.reg_confirm = ttk.Entry(frame, width=28, show="•")
        self.reg_confirm.grid(row=3, column=1, pady=6, padx=4, sticky="ew")

        btn = ttk.Button(frame, text="Đăng ký",
                         style="Primary.TButton", command=self.on_register)
        btn.grid(row=4, column=0, columnspan=2,
                 pady=(SPACE["md"], SPACE["xs"]), sticky="ew")

        for w in (self.reg_username, self.reg_password, self.reg_confirm):
            w.bind("<Return>", lambda e: self.on_register())

        frame.columnconfigure(1, weight=1)
        return frame

    def on_register(self) -> None:
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm  = self.reg_confirm.get()
        if password != confirm:
            messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp.")
            return
        try:
            user = register_user(username, password, "customer", self.app.db_path)
        except AuthError as e:
            messagebox.showerror("Đăng ký thất bại", str(e))
            return
        write_audit(
            self.app.db_path, user["id"], Action.REGISTER,
            target_type="user", target_id=str(user["id"]),
            details={"role": "customer"},
        )
        messagebox.showinfo(
            "Thành công",
            f"Đã tạo tài khoản '{username}'. Tự động đăng nhập…",
        )
        # Auto-login sau register
        try:
            session = login(username, password, self.app.db_path)
            self.app.on_login_success(session)
        except AuthError as e:
            messagebox.showerror("Lỗi", str(e))
