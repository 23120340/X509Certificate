"""
ui/admin/audit_view.py
----------------------
Bảng nhật ký hoạt động hệ thống — đáp ứng A.11.

Treeview hiển thị 100 event mới nhất (DESC theo time). Lọc theo action.
"""

import tkinter as tk
from tkinter import ttk

from services.audit import list_recent


class AuditLogFrame(ttk.Frame):
    """Bảng audit log với filter + nút Refresh."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=12)
        self.app = app

        self._build_toolbar()
        self._build_tree()
        self.refresh()

    # ── Toolbar (filter + refresh) ────────────────────────────────────────────

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(bar, text="Action:").pack(side=tk.LEFT, padx=(0, 4))
        self.action_filter = ttk.Entry(bar, width=24)
        self.action_filter.pack(side=tk.LEFT, padx=(0, 8))
        self.action_filter.bind("<Return>", lambda e: self.refresh())

        ttk.Button(bar, text="Lọc",     command=self.refresh).pack(side=tk.LEFT)
        ttk.Button(bar, text="Refresh", command=self._clear_filter_and_refresh
                   ).pack(side=tk.LEFT, padx=(6, 0))

        self.count_label = ttk.Label(bar, text="", foreground="#666")
        self.count_label.pack(side=tk.RIGHT)

    def _clear_filter_and_refresh(self) -> None:
        self.action_filter.delete(0, tk.END)
        self.refresh()

    # ── Tree ──────────────────────────────────────────────────────────────────

    def _build_tree(self) -> None:
        cols = ("id", "timestamp", "actor_id", "action", "target", "details")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=20)
        widths = {"id": 50, "timestamp": 170, "actor_id": 70,
                  "action": 150, "target": 150, "details": 240}
        anchors = {"id": "center", "timestamp": "w", "actor_id": "center",
                   "action": "w", "target": "w", "details": "w"}
        labels = {"id": "ID", "timestamp": "Thời gian (UTC)",
                  "actor_id": "Actor", "action": "Action",
                  "target": "Target", "details": "Details"}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor=anchors[c])

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.LEFT, fill=tk.Y)

    # ── Data ──────────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        action = self.action_filter.get().strip() or None
        events = list_recent(self.app.db_path, limit=200, action=action)

        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for e in events:
            target = ""
            if e["target_type"] and e["target_id"]:
                target = f"{e['target_type']}:{e['target_id']}"
            elif e["target_type"]:
                target = e["target_type"]
            self.tree.insert(
                "", tk.END,
                values=(
                    e["id"],
                    e["timestamp"][:19].replace("T", " "),  # gọn
                    e["actor_id"] if e["actor_id"] is not None else "—",
                    e["action"],
                    target,
                    (e["details_json"] or "")[:80],
                ),
            )
        self.count_label.config(text=f"{len(events)} event(s)")
