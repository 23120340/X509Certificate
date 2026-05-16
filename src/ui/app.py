"""
ui/app.py
---------
Application shell — single Tk root + single content frame.

Mỗi "page" là 1 method `show_*` clear root rồi render frame mới vào root.
Đơn giản hơn nhiều cửa sổ; cũng giống pattern SPA cho desktop.

Page hiện có:
  • show_login()              — màn hình login/register (cho cả admin + customer)
  • show_admin_dashboard()    — sau khi login với role=admin
  • show_customer_dashboard() — sau khi login với role=customer

Logout đưa app về lại show_login().

Bootstrap (`App.__init__`):
  1. init_db()              — tạo schema nếu chưa có
  2. seed_defaults()        — insert system_config defaults
  3. seed_admin_if_empty()  — tạo admin mặc định lần đầu (in pw ra console)
"""

import tkinter as tk
from tkinter import ttk

from db.connection import init_db, DEFAULT_DB_PATH
from services.auth import seed_admin_if_empty
from services.system_config import seed_defaults
from services.audit import write_audit, Action
from ui.theme import apply_theme, COLOR


DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin@123"

WINDOW_TITLE = "X.509 CA Management"
LOGIN_SIZE      = "520x420"
DASHBOARD_SIZE  = "1024x700"


class App:
    """
    State container + router. Tạo 1 Tk root, swap nội dung khi đổi page.

    Public state truy cập trong các page:
      app.root        Tk root
      app.db_path     Đường dẫn DB
      app.session     dict {id, username, role} hoặc None khi chưa login
      app.show_login(), app.show_admin_dashboard(), app.show_customer_dashboard()
      app.logout()
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.session: "dict | None" = None

        self._bootstrap()

        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)

        # Áp dụng design system (color tokens + font hierarchy + ttk styles).
        # Phải gọi sau khi tạo Tk root.
        apply_theme(self.root)

        self.content: "ttk.Frame | None" = None
        self.show_login()

    # ── Bootstrap ────────────────────────────────────────────────────────────

    def _bootstrap(self) -> None:
        """Init DB + seed defaults + seed admin nếu chưa có."""
        init_db(self.db_path)
        seed_defaults(self.db_path)
        seeded = seed_admin_if_empty(
            DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, self.db_path,
        )
        if seeded is not None:
            # ASCII-only: Windows console cp1252 không encode được tiếng Việt.
            # Message UI hiển thị tiếng Việt qua Tkinter (utf-8 native).
            print(
                f"[bootstrap] Default admin created: "
                f"username={DEFAULT_ADMIN_USERNAME!r}, "
                f"password={DEFAULT_ADMIN_PASSWORD!r}. "
                f"CHANGE IT after first login."
            )
            write_audit(
                self.db_path, seeded["id"], Action.REGISTER,
                target_type="user", target_id=str(seeded["id"]),
                details={"role": "admin", "seed": True},
            )

    # ── Router ───────────────────────────────────────────────────────────────

    def _clear_content(self) -> None:
        if self.content is not None:
            self.content.destroy()
            self.content = None

    def _set_content(self, frame: ttk.Frame, geometry: str) -> None:
        self._clear_content()
        self.content = frame
        self.content.pack(fill=tk.BOTH, expand=True)
        self.root.geometry(geometry)

    def show_login(self) -> None:
        from ui.login import LoginFrame  # import lazy → tránh circular
        self.session = None
        self.root.title(f"{WINDOW_TITLE} — Đăng nhập")
        self._set_content(LoginFrame(self.root, self), LOGIN_SIZE)

    def show_admin_dashboard(self) -> None:
        from ui.admin.dashboard import AdminDashboardFrame
        assert self.session and self.session["role"] == "admin"
        self.root.title(
            f"{WINDOW_TITLE} — Admin ({self.session['username']})"
        )
        self._set_content(
            AdminDashboardFrame(self.root, self), DASHBOARD_SIZE,
        )

    def show_customer_dashboard(self) -> None:
        from ui.customer.dashboard import CustomerDashboardFrame
        assert self.session and self.session["role"] == "customer"
        self.root.title(
            f"{WINDOW_TITLE} — Customer ({self.session['username']})"
        )
        self._set_content(
            CustomerDashboardFrame(self.root, self), DASHBOARD_SIZE,
        )

    def on_login_success(self, user: dict) -> None:
        """Gọi từ LoginFrame sau khi auth OK."""
        self.session = user
        write_audit(
            self.db_path, user["id"], Action.LOGIN,
            target_type="user", target_id=str(user["id"]),
        )
        if user["role"] == "admin":
            self.show_admin_dashboard()
        else:
            self.show_customer_dashboard()

    def logout(self) -> None:
        if self.session is not None:
            write_audit(
                self.db_path, self.session["id"], Action.LOGOUT,
                target_type="user", target_id=str(self.session["id"]),
            )
        self.show_login()

    # ── Mainloop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.root.mainloop()


def main():
    """Entry point cho CA app (gọi từ main.py)."""
    App().run()


if __name__ == "__main__":
    main()
