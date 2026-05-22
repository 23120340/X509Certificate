"""
ui/widgets/status_table.py
--------------------------
StatusFilterTreeFrame — shared widget cho 3 view dùng cùng pattern:
toolbar filter status + Treeview có color theo status + count label.

Trước refactor: csr_queue_view, cert_mgmt_view, my_certs_view đều có
~80 dòng boilerplate identical (toolbar, tree, colors, refresh logic).
Sau refactor: mỗi view chỉ cần khai báo schema + fetch function.

Usage:
    self.table = StatusFilterTreeFrame(
        self,
        columns=[
            ("id",          "ID",          50),
            ("common_name", "Domain (CN)", 180),
            ("status",      "Status",       80),
            ...
        ],
        status_values=("pending", "approved", "rejected", "all"),
        status_colors={"pending": "#d68910", ...},
        default_status_index=0,
        fetch_fn=lambda status: list_all_csr(self.app.db_path, status=...),
        row_mapper=lambda r: (r["id"], r["common_name"], ...),
        count_unit="CSR",
    )
    self.table.pack(fill=tk.BOTH, expand=True)
    self.table.refresh()

Caller dùng:
  • self.table.refresh()           — re-fetch + redraw
  • self.table.selected_id()       — int hoặc None (đã show warning)
  • self.table.bind_double_click(callback)  — open detail on dblclick
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Any


class StatusFilterTreeFrame(ttk.Frame):
    """Frame: [Filter combobox + Refresh + count] + [Treeview + scrollbar].

    Action buttons KHÔNG nằm trong widget này — caller tự render bên dưới
    để mỗi view có button set riêng (CSR có Approve/Reject, Cert có
    Revoke/Renew, My Certs chỉ có View/Download...).
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        columns: list,                # list[(key, label, width)]
        status_values: tuple,         # ("pending","approved","rejected","all")
        status_colors: dict,          # {"pending": "#d68910", ...}
        default_status_index: int,    # index trong status_values
        fetch_fn: Callable[[str], list],   # (status_str) → list[dict]
        row_mapper: Callable[[dict], tuple],  # row → values tuple
        status_field: str = "status", # field trong row dùng cho color tag
        id_field: str = "id",          # field dùng cho iid + selected_id
        count_unit: str = "mục",       # "12 CSR" / "5 cert"
        tree_height: int = 14,
    ):
        super().__init__(parent)
        self._columns       = columns
        self._fetch_fn      = fetch_fn
        self._row_mapper    = row_mapper
        self._status_field  = status_field
        self._id_field      = id_field
        self._count_unit    = count_unit
        self._status_colors = status_colors

        self._build_toolbar(status_values, default_status_index)
        self._build_tree(tree_height)
        self._apply_status_colors()

    # ── Build UI ────────────────────────────────────────────────────────────

    def _build_toolbar(self, status_values, default_idx) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT, padx=(0, 4))
        self.status_combo = ttk.Combobox(
            bar, values=status_values, state="readonly", width=12,
        )
        self.status_combo.current(default_idx)
        self.status_combo.pack(side=tk.LEFT)
        self.status_combo.bind("<<ComboboxSelected>>",
                               lambda e: self.refresh())
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))
        self.count_label = ttk.Label(bar, text="", foreground="#666")
        self.count_label.pack(side=tk.RIGHT)

    def _build_tree(self, height: int) -> None:
        col_keys = [c[0] for c in self._columns]
        self.tree = ttk.Treeview(
            self, columns=col_keys, show="headings", height=height,
        )
        for key, label, width in self._columns:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        vsb.place(in_=self.tree, relx=1.0, x=-1, rely=0, relheight=1.0,
                  anchor="ne")

    def _apply_status_colors(self) -> None:
        for status, color in self._status_colors.items():
            self.tree.tag_configure(status, foreground=color)

    # ── Public API ──────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Re-fetch data + redraw tree."""
        status = self.status_combo.get()
        rows = self._fetch_fn(status)

        for iid in self.tree.get_children():
            self.tree.delete(iid)

        for r in rows:
            tag = r.get(self._status_field, "")
            self.tree.insert(
                "", tk.END, iid=str(r[self._id_field]),
                values=self._row_mapper(r),
                tags=(tag,) if tag else (),
            )
        self.count_label.config(text=f"{len(rows)} {self._count_unit}")

    def selected_id(self) -> "int | None":
        """Trả về id row đang chọn; show warning nếu chưa chọn."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn",
                                    "Hãy chọn 1 dòng trong bảng.")
            return None
        try:
            return int(sel[0])
        except ValueError:
            return None

    def bind_double_click(self, callback: Callable[[], None]) -> None:
        """Bind double-click trên tree → callback (thường là 'xem chi tiết')."""
        self.tree.bind("<Double-Button-1>", lambda e: callback())

    def current_status(self) -> str:
        """Trả về status filter đang chọn."""
        return self.status_combo.get()
