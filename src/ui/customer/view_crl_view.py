"""
ui/customer/view_crl_view.py
----------------------------
B.8 — Tra cứu danh sách thu hồi chứng nhận của toàn hệ thống.

Layout:
  • Header: thông tin CRL hiện hành (issuer, this_update, next_update, count)
  • Bảng: list serial + revocation_date + common_name (nếu match DB)
  • Filter theo serial (substring) hoặc CN (substring)
"""

import tkinter as tk
from tkinter import ttk

from services.crl_publish import (
    get_published_crl_info, list_crl_entries, DEFAULT_CRL_PATH,
)


class ViewCRLFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Tra cứu CRL (B.8)",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Danh sách các chứng chỉ đã bị thu hồi do Root CA của hệ "
                "thống công bố. CRL là thông tin công khai — bất kỳ ai cũng "
                "có thể tra cứu để biết một cert có còn hợp lệ hay không."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        self._build_header_section()
        self._build_filter()
        self._build_tree()
        self.refresh()

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header_section(self) -> None:
        self.header_box = ttk.LabelFrame(
            self, text="CRL hiện hành", padding=12,
        )
        self.header_box.pack(fill=tk.X)

    # ── Filter ────────────────────────────────────────────────────────────────

    def _build_filter(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(12, 4))
        ttk.Label(bar, text="Tìm (serial hoặc CN):").pack(side=tk.LEFT, padx=(0, 4))
        self.filter_entry = ttk.Entry(bar, width=32)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_entry.bind("<Return>", lambda e: self._apply_filter())
        ttk.Button(bar, text="Lọc",
                   command=self._apply_filter).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(bar, text="Clear",
                   command=self._clear_filter).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(12, 0))
        self.count_label = ttk.Label(bar, text="", foreground="#666")
        self.count_label.pack(side=tk.RIGHT)

    def _clear_filter(self) -> None:
        self.filter_entry.delete(0, tk.END)
        self._apply_filter()

    def _apply_filter(self) -> None:
        q = self.filter_entry.get().strip().lower()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for e in self._cached_entries:
            if q and q not in e["serial_hex"].lower() \
               and q not in e["common_name"].lower():
                continue
            self.tree.insert(
                "", tk.END,
                values=(
                    e["serial_hex"][:48] + ("…" if len(e["serial_hex"]) > 48 else ""),
                    e["common_name"] or "—",
                    e["owner_username"] or "—",
                    e["revocation_date"][:19].replace("T", " "),
                ),
            )
        self.count_label.config(
            text=f"{len(self.tree.get_children())} / {len(self._cached_entries)} entry",
        )

    # ── Tree ──────────────────────────────────────────────────────────────────

    def _build_tree(self) -> None:
        cols = ("serial", "common_name", "owner", "revocation_date")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        labels = {
            "serial": "Serial",
            "common_name": "Domain (CN)",
            "owner": "Owner",
            "revocation_date": "Thu hồi lúc",
        }
        widths = {"serial": 320, "common_name": 200, "owner": 100,
                  "revocation_date": 140}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        vsb.place(in_=self.tree, relx=1.0, x=-1, rely=0, relheight=1.0,
                  anchor="ne")

    # ── Refresh ───────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        # Header
        for child in self.header_box.winfo_children():
            child.destroy()
        info = get_published_crl_info(DEFAULT_CRL_PATH)
        if info is None:
            ttk.Label(
                self.header_box,
                text=(
                    "Chưa có CRL nào được publish. Admin cần bấm "
                    "\"Publish CRL Now\" trước."
                ),
                foreground="#888",
            ).pack(anchor="w")
            self._cached_entries = []
        else:
            for label, key in [
                ("Issuer",        "issuer"),
                ("This update",   "this_update"),
                ("Next update",   "next_update"),
                ("Tổng revoked",  "revoked_count"),
            ]:
                row = ttk.Frame(self.header_box)
                row.pack(anchor="w", pady=1)
                ttk.Label(
                    row, text=f"{label}:",
                    font=("Segoe UI", 9, "bold"), width=14,
                ).pack(side=tk.LEFT)
                ttk.Label(row, text=str(info[key])).pack(side=tk.LEFT)
            self._cached_entries = list_crl_entries(
                DEFAULT_CRL_PATH, db_path=self.app.db_path,
            )
        self._apply_filter()
