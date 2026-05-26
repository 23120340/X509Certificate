"""
ui/widgets/modal.py
-------------------
Helper init modal dialog — gom boilerplate Tk lặp ở 7+ Dialog class.

Trước:
    class RevokeCertDialog(tk.Toplevel):
        def __init__(self, parent, app, rec, on_done=None):
            super().__init__(parent)
            self.title("Revoke cert #...")
            self.geometry("440x300")
            self.resizable(False, False)
            self.transient(parent)
            self.grab_set()
            frame = ttk.Frame(self, padding=16)
            frame.pack(fill=tk.BOTH, expand=True)
            # ... form fields ...

Sau:
    class RevokeCertDialog(tk.Toplevel):
        def __init__(self, parent, app, rec, on_done=None):
            super().__init__(parent)
            body = init_modal(self, parent=parent,
                              title="Revoke cert #...",
                              geometry="440x300")
            # ... form fields trong body ...

Tiết kiệm ~6 dòng/dialog × 7 dialogs = ~42 dòng. Quan trọng hơn: tập trung
default style (padding=16, grab_set) vào 1 chỗ — đổi 1 lần áp dụng toàn UI.
"""

import tkinter as tk
from tkinter import ttk


def init_modal(
    toplevel: tk.Toplevel,
    *,
    parent: tk.Misc,
    title: str,
    geometry: str = "440x300",
    resizable: bool = False,
    padding: int = 16,
) -> ttk.Frame:
    """Set up modal dialog properties + tạo body frame chính.

    Args:
        toplevel: instance Toplevel (caller phải tự `super().__init__(parent)`)
        parent: widget cha (để transient + center context)
        title: tiêu đề cửa sổ
        geometry: kích thước "WxH" hoặc None để Tk tự chỉnh
        resizable: cho phép resize không (default False — modal nên cố định)
        padding: padding của body frame

    Returns:
        ttk.Frame — body frame đã `.pack(side=TOP, fill=BOTH, expand=True)`,
        caller có thể dùng `.pack()` HOẶC `.grid()` cho widget con trong body.

    Note: body được pack `side=TOP` để `make_button_row()` có thể pack 1
    footer frame riêng với `side=BOTTOM` ở toplevel — KHÔNG mix layout trong
    cùng 1 parent (mix grid/pack trên cùng parent là lỗi Tk classic gây
    button không hiện).
    """
    toplevel.title(title)
    if geometry:
        toplevel.geometry(geometry)
    toplevel.resizable(resizable, resizable)
    toplevel.transient(parent)
    toplevel.grab_set()

    body = ttk.Frame(toplevel, padding=padding)
    body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    return body


def fit_to_content(toplevel: tk.Toplevel) -> None:
    """Force modal to grow if content + buttons exceed the requested geometry.

    Why: `init_modal` sets a fixed `geometry("WxH")` for predictable size.
    Khi content thật (label dài, Text widget, warning wrap…) cao hơn H, Tk
    pack engine sẽ clip widget cuối cùng (thường là button bar ở BOTTOM)
    → user thấy "Approve/Reject button bị che mất". `wm_minsize` ép Tk
    grow window lên required size, bất kể `resizable(False, False)`.

    Gọi hàm này SAU khi đã pack/grid hết content + button row.
    """
    toplevel.update_idletasks()
    req_w = toplevel.winfo_reqwidth()
    req_h = toplevel.winfo_reqheight()
    toplevel.minsize(req_w, req_h)


def make_button_row(
    parent: tk.Misc,
    *,
    submit_label: str = "OK",
    submit_command=None,
    cancel_label: str = "Hủy",
    cancel_command=None,
    submit_style: str = "Primary.TButton",
) -> ttk.Frame:
    """Render hàng button [Cancel] [Submit] ở dưới đáy modal.

    QUAN TRỌNG: bar được pack vào **toplevel** (sibling của body), KHÔNG
    vào `parent` — để tránh xung đột nếu body dùng `.grid()` cho form fields.
    Mix grid + pack trên cùng parent là lỗi Tk im lặng (button không hiện).

    Args:
        parent: thường là body frame trả về từ `init_modal()`. Hàm dùng
                `parent.winfo_toplevel()` để pack bar vào level cao nhất.
        submit_label/command: nút action chính (Phát hành / Renew / Revoke...)
        cancel_label/command: nút hủy (default = destroy toplevel)
        submit_style: ttk style cho nút primary

    Returns: ttk.Frame chứa button row.
    """
    toplevel = parent.winfo_toplevel()
    bar = ttk.Frame(toplevel, padding=(16, 0, 16, 12))
    # side=BOTTOM + pack trước/sau body đều OK vì pack engine reserve space
    # cho cả 2 — body expand=True chiếm phần còn lại sau khi bar lấy bottom.
    bar.pack(side=tk.BOTTOM, fill=tk.X)

    if cancel_command is None:
        cancel_command = toplevel.destroy

    if submit_command is not None:
        try:
            ttk.Button(bar, text=submit_label, command=submit_command,
                       style=submit_style).pack(side=tk.RIGHT, padx=4)
        except tk.TclError:
            ttk.Button(bar, text=submit_label,
                       command=submit_command).pack(side=tk.RIGHT, padx=4)

    ttk.Button(bar, text=cancel_label,
               command=cancel_command).pack(side=tk.RIGHT, padx=4)

    fit_to_content(toplevel)
    return bar
