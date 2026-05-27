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
from services.remote_csr_client import check_admin_api_health, RemoteCSRClientError
from ui.theme import COLOR, SPACE, font


class LoginFrame(ttk.Frame):
    """Frame chứa form login + form register, switch qua notebook tab."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        self._build_header()
        self._build_notebook()
        self._build_lan_panel()

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

    def _build_lan_panel(self) -> None:
        outer = ttk.Frame(self)
        outer.pack(fill=tk.X, pady=(SPACE["md"], 0))

        self.advanced_mode = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            outer,
            text="Advanced mode",
            variable=self.advanced_mode,
            command=self._toggle_advanced_mode,
        ).pack(anchor="w")

        box = ttk.LabelFrame(outer, text="LAN CSR mode", padding=12)
        self.lan_options = box

        initial_mode = "client" if getattr(self.app, "remote_csr_api_url", "") else "offline"
        self.lan_mode = tk.StringVar(value=initial_mode)
        mode_row = ttk.Frame(box)
        mode_row.grid(row=0, column=0, columnspan=5, sticky="w")
        ttk.Radiobutton(mode_row, text="Offline", value="offline",
                        variable=self.lan_mode,
                        command=self._update_lan_mode).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(mode_row, text="Máy Admin nhận CSR", value="admin",
                        variable=self.lan_mode,
                        command=self._update_lan_mode).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(mode_row, text="Máy Client gửi CSR", value="client",
                        variable=self.lan_mode,
                        command=self._update_lan_mode).pack(side=tk.LEFT)

        ttk.Label(box, text="Admin bind:").grid(row=1, column=0, sticky="e", pady=6, padx=4)
        self.admin_host_entry = ttk.Entry(box, width=16)
        self.admin_host_entry.grid(row=1, column=1, sticky="ew", pady=6, padx=4)
        self.admin_host_entry.insert(0, "0.0.0.0")
        ttk.Label(box, text="Port:").grid(row=1, column=2, sticky="e", pady=6, padx=4)
        self.admin_port_entry = ttk.Entry(box, width=8)
        self.admin_port_entry.grid(row=1, column=3, sticky="w", pady=6, padx=4)
        self.admin_port_entry.insert(0, "8787")
        self.admin_start_btn = ttk.Button(box, text="Bật CSR API",
                                          command=self.on_start_admin_api)
        self.admin_start_btn.grid(row=1, column=4, sticky="ew", pady=6, padx=4)

        ttk.Label(box, text="Admin API URL:").grid(row=2, column=0, sticky="e", pady=6, padx=4)
        self.client_url_entry = ttk.Entry(box, width=42)
        self.client_url_entry.grid(row=2, column=1, columnspan=3, sticky="ew", pady=6, padx=4)
        self.client_url_entry.insert(
            0, getattr(self.app, "remote_csr_api_url", "") or "http://10.0.17.102:8787"
        )
        self.client_apply_btn = ttk.Button(box, text="Dùng URL này",
                                           command=self.on_apply_client_api)
        self.client_apply_btn.grid(row=2, column=4, sticky="ew", pady=6, padx=4)

        ttk.Label(box, text="Token:").grid(row=3, column=0, sticky="e", pady=6, padx=4)
        self.lan_token_entry = ttk.Entry(box, width=42, show="*")
        self.lan_token_entry.grid(row=3, column=1, columnspan=3, sticky="ew", pady=6, padx=4)
        self.lan_token_entry.insert(0, getattr(self.app, "remote_csr_api_token", ""))
        self.client_test_btn = ttk.Button(box, text="Test API",
                                          command=self.on_test_client_api)
        self.client_test_btn.grid(row=3, column=4, sticky="ew", pady=6, padx=4)

        self.lan_status = ttk.Label(
            box, text="Offline: dùng database cục bộ trên máy này.",
            style="Subtle.TLabel",
        )
        self.lan_status.grid(row=4, column=0, columnspan=5, sticky="w", pady=(4, 0))
        box.columnconfigure(1, weight=1)
        self._update_lan_mode()

    def _toggle_advanced_mode(self) -> None:
        if self.advanced_mode.get():
            self.lan_options.pack(fill=tk.X, pady=(SPACE["xs"], 0))
        else:
            self.lan_options.pack_forget()

    def _update_lan_mode(self) -> None:
        mode = self.lan_mode.get()
        admin_state = tk.NORMAL if mode == "admin" else tk.DISABLED
        client_state = tk.NORMAL if mode == "client" else tk.DISABLED
        for widget in (self.admin_host_entry, self.admin_port_entry, self.admin_start_btn):
            widget.configure(state=admin_state)
        for widget in (self.client_url_entry, self.client_apply_btn, self.client_test_btn):
            widget.configure(state=client_state)
        self.lan_token_entry.configure(
            state=tk.NORMAL if mode in ("admin", "client") else tk.DISABLED
        )
        if mode == "offline":
            self.app.set_remote_csr_api("", "")
            self.lan_status.configure(text="Offline: dùng database cục bộ trên máy này.")
        elif mode == "admin":
            self.lan_status.configure(text="Admin mode: bật API rồi đăng nhập admin để duyệt CSR.")
        else:
            self.lan_status.configure(text="Client mode: nhập URL máy Admin, Test API, rồi đăng nhập customer.")

    def on_start_admin_api(self) -> None:
        try:
            port = int(self.admin_port_entry.get().strip())
            if not (1024 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Port không hợp lệ", "Port phải từ 1024 đến 65535.")
            return
        host = self.admin_host_entry.get().strip() or "0.0.0.0"
        try:
            self.app.start_csr_api(host=host, port=port,
                                   token=self.lan_token_entry.get())
        except OSError as e:
            messagebox.showerror("Không bật được CSR API", str(e))
            return
        self.lan_status.configure(
            text=f"CSR API đã bật tại {host}:{port}. Client dùng http://<IP máy này>:{port}."
        )
        messagebox.showinfo("CSR API đã bật", f"Server đang nghe tại {host}:{port}")

    def on_apply_client_api(self) -> None:
        url = self.client_url_entry.get().strip().rstrip("/")
        if not url:
            messagebox.showerror("Thiếu URL", "Nhập Admin API URL, ví dụ http://10.0.17.102:8787")
            return
        self.app.set_remote_csr_api(url, self.lan_token_entry.get())
        self.lan_status.configure(text=f"Client mode đang dùng Admin API: {url}")
        messagebox.showinfo("Đã bật Client LAN", "Sau khi đăng nhập customer, Submit CSR sẽ gửi tới Admin API.")

    def on_test_client_api(self) -> None:
        url = self.client_url_entry.get().strip().rstrip("/")
        try:
            data = check_admin_api_health(api_url=url)
        except RemoteCSRClientError as e:
            messagebox.showerror("Không kết nối được Admin API", str(e))
            return
        self.app.set_remote_csr_api(url, self.lan_token_entry.get())
        self.lan_status.configure(text=f"Admin API OK: {url}")
        messagebox.showinfo("Admin API OK", f"Kết nối thành công tới {url}\nService: {data.get('service', 'csr-api')}")

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
            text="Mặc định lần đầu: admin / Admin@123.",
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
