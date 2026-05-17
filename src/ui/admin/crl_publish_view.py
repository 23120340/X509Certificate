"""
ui/admin/crl_publish_view.py
----------------------------
Cập nhật CRL — đáp ứng A.10.

  • Hiển thị metadata CRL hiện hành (issuer, this_update, next_update, count)
  • Nút Publish CRL Now: snapshot DB → build + ký CRL → ghi file + sync OCSP DB
  • Hiển thị số serial sẽ vào CRL trước khi publish (sanity check)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from services.audit import write_audit, Action
from services.crl_publish import (
    publish_crl, get_published_crl_info, snapshot_revoked_serials,
    DEFAULT_CRL_PATH, DEFAULT_OCSP_DB_PATH, CRLPublishError,
)


class CRLPublishFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Cập nhật CRL",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Snapshot trạng thái revoked từ DB → build CRL (ký bằng Root "
                "CA active) → ghi file. Cả CRL HTTP server (port 8889) và "
                "OCSP responder (port 8888) sẽ phục vụ data mới sau khi publish."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        self._build_current_info()
        self._build_pending_info()
        self._build_actions()
        self.refresh()

    def _build_current_info(self) -> None:
        self.current_box = ttk.LabelFrame(
            self, text="CRL hiện hành (đã publish)", padding=12,
        )
        self.current_box.pack(fill=tk.X)

    def _build_pending_info(self) -> None:
        self.pending_box = ttk.LabelFrame(
            self, text="Snapshot DB (sẽ vào CRL khi publish)", padding=12,
        )
        self.pending_box.pack(fill=tk.X, pady=(12, 0))

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(16, 0))
        ttk.Button(bar, text="📢 Publish CRL Now",
                   command=self.on_publish).pack(side=tk.LEFT)
        ttk.Button(bar, text="Refresh",
                   command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))

    def refresh(self) -> None:
        # Current CRL info
        for child in self.current_box.winfo_children():
            child.destroy()
        info = get_published_crl_info()
        if info is None:
            ttk.Label(
                self.current_box,
                text="Chưa có CRL được publish (file certs/crl.pem không tồn tại).",
                foreground="#888",
            ).pack(anchor="w")
        else:
            for label, key in [
                ("File",           "crl_path"),
                ("Issuer",         "issuer"),
                ("This update",    "this_update"),
                ("Next update",    "next_update"),
                ("Revoked count",  "revoked_count"),
                ("File size",      "file_size"),
            ]:
                row = ttk.Frame(self.current_box)
                row.pack(anchor="w", pady=1)
                ttk.Label(
                    row, text=f"{label}:",
                    font=font("label"), width=16,
                ).pack(side=tk.LEFT)
                val = info[key]
                if key == "file_size":
                    val = f"{val} bytes"
                ttk.Label(row, text=str(val)).pack(side=tk.LEFT)

        # Pending: snapshot từ DB
        for child in self.pending_box.winfo_children():
            child.destroy()
        serials = snapshot_revoked_serials(self.app.db_path)
        ttk.Label(
            self.pending_box,
            text=f"Số serial revoked trong DB: {len(serials)}",
            font=font("heading_sm"),
        ).pack(anchor="w")
        if serials:
            preview = ", ".join(f"{s:x}"[:16] for s in serials[:5])
            extra = f" (+{len(serials) - 5} nữa)" if len(serials) > 5 else ""
            ttk.Label(
                self.pending_box,
                text=f"Preview (hex): {preview}{extra}",
                foreground="#666", font=font("mono"),
            ).pack(anchor="w", pady=(4, 0))

        # Diff so với current CRL
        if info is not None:
            db_count = len(serials)
            crl_count = info["revoked_count"]
            if db_count != crl_count:
                ttk.Label(
                    self.pending_box,
                    text=(
                        f"⚠ DB có {db_count} revoked, CRL hiện có {crl_count} "
                        f"→ Publish để đồng bộ."
                    ),
                    foreground="#d68910",
                ).pack(anchor="w", pady=(4, 0))
            else:
                ttk.Label(
                    self.pending_box,
                    text="✓ Số serial trùng với CRL hiện hành.",
                    foreground="#1e8449",
                ).pack(anchor="w", pady=(4, 0))

    def on_publish(self) -> None:
        try:
            result = publish_crl(
                admin_id=self.app.session["id"],
                db_path=self.app.db_path,
                crl_path=DEFAULT_CRL_PATH,
                ocsp_db_path=DEFAULT_OCSP_DB_PATH,
            )
        except CRLPublishError as e:
            messagebox.showerror("Publish CRL thất bại", str(e))
            return

        write_audit(
            self.app.db_path, self.app.session["id"], Action.CRL_PUBLISHED,
            target_type="crl", target_id=result["crl_path"],
            details={
                "revoked_count": result["revoked_count"],
                "this_update":   result["this_update"],
                "next_update":   result["next_update"],
                "ocsp_db_synced": result["ocsp_db_path"] is not None,
            },
        )
        messagebox.showinfo(
            "Đã publish",
            f"CRL đã ghi vào:\n{result['crl_path']}\n\n"
            f"  • {result['revoked_count']} serial revoked\n"
            f"  • this_update = {result['this_update']}\n"
            f"  • next_update = {result['next_update']}\n\n"
            f"OCSP DB đã sync: {result['ocsp_db_path']}",
        )
        self.refresh()
