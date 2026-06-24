"""
ui/customer/upload_external_view.py
-----------------------------------
B.9 — Upload cert ngoài để theo dõi + chạy 5 bước verify.

Layout:
  • Tab "Upload": paste PEM hoặc Browse file + notes + nút Upload → preview
                    + nút Save vào DB.
  • Tab "Của tôi": bảng list các cert đã upload + nút Xem chi tiết / Verify /
                    Xóa.
  • Verify dialog: nhập hostname → chạy `core.verify.verify_certificate_full`
                    với trust store của hệ thống → hiển thị 5 bước + tổng kết.

Lưu ý: verify Bước 4 (CRL) + Bước 5 (OCSP) gọi HTTP đến URL trong cert (Prod
CRL :8889, Prod OCSP :8888). Prod servers tự khởi động cùng app trong
`ui/app.py` — không cần thao tác thủ công nữa.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from ui.theme import font, COLOR
from services.audit import write_audit, Action
from services.ca_admin import publish_active_to_trust_store
from services.external_certs import (
    save_external_cert, list_external_certs, get_external_cert,
    delete_external_cert, parse_cert_summary, ExternalCertError,
)
from ui.common import CertDetailDialog, fmt_local


from config import TRUST_STORE_DIR


class UploadExternalFrame(ttk.Frame):

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Upload chứng chỉ ngoài + Verify",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Upload bất kỳ cert X.509 nào (kể cả không thuộc bạn) để "
                "lưu trữ + theo dõi + chạy 5 bước verify với Trust Store "
                "của hệ thống. Tab \"Của tôi\" liệt kê các cert đã upload."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)
        nb.add(self._build_upload_tab(nb),  text="Upload")
        nb.add(self._build_list_tab(nb),    text="Của tôi")

    # ── Upload tab ────────────────────────────────────────────────────────────

    def _build_upload_tab(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)

        # Input header (TOP)
        top = ttk.Frame(frame)
        top.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(
            top, text="📂 Browse file…", command=self._browse_file,
        ).pack(side=tk.LEFT)
        ttk.Label(
            top, text="hoặc paste PEM bên dưới:",
            foreground="#666",
        ).pack(side=tk.LEFT, padx=(12, 0))

        # Preview panel + action/notes rows được pack ở ĐÁY (side=BOTTOM) để
        # luôn dành sẵn chỗ — pem_text (expand) fill phần giữa. Trước đây preview
        # bị đẩy xuống dưới fold do pem_text expand chiếm hết chiều cao.
        self.preview_box = ttk.LabelFrame(
            frame, text="Xem trước (preview)", padding=10,
        )
        self.preview_box.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        self.preview_label = ttk.Label(
            self.preview_box, text="(chưa có — bấm Preview để xem)",
            foreground="#888", font=font("mono"), justify=tk.LEFT,
        )
        self.preview_label.pack(anchor="w", fill=tk.X)

        action_row = ttk.Frame(frame)
        action_row.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0))
        ttk.Button(action_row, text="📋 Xem chi tiết cert",
                   command=self._on_view_detail).pack(side=tk.LEFT)
        ttk.Button(action_row, text="💾 Upload + Lưu",
                   command=self._on_upload).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(action_row, text="Clear",
                   command=self._on_clear).pack(side=tk.LEFT, padx=(8, 0))

        notes_row = ttk.Frame(frame)
        notes_row.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))
        ttk.Label(notes_row, text="Ghi chú:").pack(side=tk.LEFT, padx=(0, 4))
        self.notes_entry = ttk.Entry(notes_row, width=50)
        self.notes_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # PEM input — fill phần giữa còn lại
        self.pem_text = tk.Text(
            frame, height=12, font=font("mono"), wrap=tk.NONE,
        )
        self.pem_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(6, 0))
        # Tự động preview khi rời ô nhập (cả browse lẫn paste) — không cần nút.
        self.pem_text.bind("<FocusOut>", lambda e: self._auto_preview())
        return frame

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Chọn cert file (PEM hoặc DER)",
            filetypes=(
                ("Certificate", "*.crt *.cer *.pem *.der"),
                ("All files", "*.*"),
            ),
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                content = f.read()
        except OSError as e:
            messagebox.showerror("Lỗi", f"Không đọc được file: {e}")
            return
        # Hiển thị PEM (nếu DER thì base64 hiển thị có thể không đẹp; convert)
        try:
            summary = parse_cert_summary(content)
        except ExternalCertError as e:
            messagebox.showerror("Lỗi parse", str(e))
            return
        # Re-encode sang PEM để text area hiển thị
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        try:
            cert = x509.load_pem_x509_certificate(content)
        except ValueError:
            cert = x509.load_der_x509_certificate(content)
        pem_str = cert.public_bytes(Encoding.PEM).decode("ascii")
        self.pem_text.delete("1.0", tk.END)
        self.pem_text.insert("1.0", pem_str)
        self._show_preview(summary)

    def _get_pem_bytes(self) -> "bytes | None":
        content = self.pem_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Trống", "Hãy paste PEM hoặc browse file.")
            return None
        return content.encode("ascii", errors="replace")

    def _auto_preview(self) -> None:
        """Tự động preview khi rời ô PEM — im lặng nếu chưa parse được."""
        content = self.pem_text.get("1.0", tk.END).strip()
        if not content:
            return
        try:
            summary = parse_cert_summary(content.encode("ascii", errors="replace"))
        except ExternalCertError:
            return
        self._show_preview(summary)

    def _on_view_detail(self) -> None:
        """Mở CertDetailDialog (decode đầy đủ) cho cert đang nhập trong ô PEM."""
        data = self._get_pem_bytes()
        if data is None:
            return
        try:
            summary = parse_cert_summary(data)
        except ExternalCertError as e:
            messagebox.showerror("Lỗi parse", str(e))
            return
        self._show_preview(summary)
        cn = next(
            (p.split("=", 1)[1] for p in summary["subject"].split(",")
             if p.strip().upper().startswith("CN=")),
            summary["subject"],
        )
        CertDetailDialog(self, {
            "id":               "—",
            "serial_hex":       summary["serial_hex"],
            "common_name":      cn,
            "cert_pem":         data,
            "not_valid_before": summary["not_valid_before"],
            "not_valid_after":  summary["not_valid_after"],
            "issued_at":        None,
            "status":           "external",
            "owner_username":   self.app.session["username"],
            "renewed_from_id":  None,
            "revoked_at":       None,
        })

    def _show_preview(self, s: dict) -> None:
        self.preview_label.config(foreground="#333", text=(
            f"Subject:     {s['subject']}\n"
            f"Issuer:      {s['issuer']}\n"
            f"Serial:      {s['serial_hex']}\n"
            f"Valid:       {fmt_local(s['not_valid_before'])} → {fmt_local(s['not_valid_after'])}\n"
            f"SAN (DNS):   {', '.join(s['san_dns']) or '—'}\n"
            f"Public key:  {s['public_key']}\n"
            f"Fingerprint: {s['fingerprint_sha256']}"
        ))

    def _on_upload(self) -> None:
        data = self._get_pem_bytes()
        if data is None:
            return
        notes = self.notes_entry.get().strip()
        try:
            rec = save_external_cert(
                self.app.session["id"], data, notes, self.app.db_path,
            )
        except ExternalCertError as e:
            messagebox.showerror("Upload thất bại", str(e))
            return
        write_audit(
            self.app.db_path, self.app.session["id"], Action.EXTERNAL_UPLOADED,
            target_type="external_cert", target_id=str(rec["id"]),
            details={
                "fingerprint": rec["fingerprint_sha256"],
                "subject": rec["subject"],
                "issuer": rec["issuer"],
            },
        )
        messagebox.showinfo(
            "Đã upload",
            f"Cert đã được lưu (id={rec['id']}). "
            f"Sang tab \"Của tôi\" để verify.",
        )
        self._on_clear()
        self._refresh_list()

    def _on_clear(self) -> None:
        self.pem_text.delete("1.0", tk.END)
        self.notes_entry.delete(0, tk.END)
        self.preview_label.config(
            foreground="#888", text="(chưa có — bấm Preview để xem)",
        )

    # ── List tab ──────────────────────────────────────────────────────────────

    def _build_list_tab(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)

        bar = ttk.Frame(frame)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(bar, text="📋 Xem chi tiết",
                   command=self._on_view).pack(side=tk.LEFT)
        ttk.Button(bar, text="🔍 Verify (5 bước)",
                   command=self._on_verify).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="🗑 Xóa",
                   command=self._on_delete).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(bar, text="Refresh",
                   command=self._refresh_list).pack(side=tk.LEFT, padx=(8, 0))

        cols = ("id", "subject", "issuer", "serial", "not_valid_after",
                "fingerprint", "uploaded_at")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=12)
        labels = {
            "id": "ID", "subject": "Subject", "issuer": "Issuer",
            "serial": "Serial", "not_valid_after": "Hết hạn",
            "fingerprint": "Fingerprint",
            "uploaded_at": "Upload lúc",
        }
        widths = {"id": 40, "subject": 200, "issuer": 200, "serial": 140,
                  "not_valid_after": 140, "fingerprint": 130,
                  "uploaded_at": 140}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        vsb.place(in_=self.tree, relx=1.0, x=-1, rely=0, relheight=1.0,
                  anchor="ne")
        self._refresh_list()
        return frame

    def _refresh_list(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for r in list_external_certs(self.app.session["id"], self.app.db_path):
            self.tree.insert(
                "", tk.END, iid=str(r["id"]),
                values=(
                    r["id"],
                    r.get("subject") or "?",
                    r.get("issuer") or "?",
                    r.get("serial_hex", "")[:24] + (
                        "…" if len(r.get("serial_hex", "")) > 24 else ""
                    ),
                    fmt_local(r.get("not_valid_after")),
                    r["fingerprint_sha256"][:16] + "…",
                    fmt_local(r["uploaded_at"]),
                ),
            )

    def _selected_id(self) -> "int | None":
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Hãy chọn cert trong bảng.")
            return None
        return int(sel[0])

    def _on_view(self) -> None:
        cid = self._selected_id()
        if cid is None:
            return
        rec = get_external_cert(cid, self.app.session["id"], self.app.db_path)
        if rec is None:
            return
        # Tái dùng CertDetailDialog — cần các field tương thích
        try:
            summary = parse_cert_summary(bytes(rec["cert_pem"]))
        except ExternalCertError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        adapted = {
            "id":               rec["id"],
            "serial_hex":       summary["serial_hex"],
            "common_name":      summary["subject"].split(",")[-1].replace("CN=", ""),
            "cert_pem":         rec["cert_pem"],
            "not_valid_before": summary["not_valid_before"],
            "not_valid_after":  summary["not_valid_after"],
            "issued_at":        rec["uploaded_at"],
            "status":           "external",
            "owner_username":   self.app.session["username"],
            "renewed_from_id":  None,
            "revoked_at":       None,
        }
        CertDetailDialog(self, adapted)

    def _on_verify(self) -> None:
        cid = self._selected_id()
        if cid is None:
            return
        rec = get_external_cert(cid, self.app.session["id"], self.app.db_path)
        if rec is None:
            return
        VerifyExternalDialog(self, self.app, rec)

    def _on_delete(self) -> None:
        cid = self._selected_id()
        if cid is None:
            return
        if not messagebox.askyesno("Xác nhận", f"Xóa external cert #{cid}?"):
            return
        try:
            delete_external_cert(cid, self.app.session["id"], self.app.db_path)
        except ExternalCertError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        write_audit(
            self.app.db_path, self.app.session["id"], Action.EXTERNAL_DELETED,
            target_type="external_cert", target_id=str(cid),
        )
        self._refresh_list()


# ── Verify dialog ─────────────────────────────────────────────────────────────

class VerifyExternalDialog(tk.Toplevel):
    """Modal chạy `verify_certificate_full` cho 1 external cert."""

    def __init__(self, parent: tk.Misc, app, cert_rec: dict):
        super().__init__(parent)
        self.app = app
        self.cert_rec = cert_rec

        self.title(f"Verify external cert #{cert_rec['id']}")
        self.geometry("780x600")
        self.transient(parent)

        # Default hostname = CN của cert
        try:
            summary = parse_cert_summary(bytes(cert_rec["cert_pem"]))
            default_host = (summary["san_dns"][0] if summary["san_dns"]
                            else summary["subject"].split("CN=")[-1].split(",")[0])
        except Exception:
            default_host = ""

        top = ttk.Frame(self, padding=12)
        top.pack(fill=tk.X)
        ttk.Label(top, text="Hostname:").grid(row=0, column=0, sticky="e", padx=4)
        self.host_entry = ttk.Entry(top, width=36)
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=4)
        self.host_entry.insert(0, default_host)
        ttk.Button(top, text="Chạy 5 bước",
                   command=self._run).grid(row=0, column=2, padx=4)
        top.columnconfigure(1, weight=1)

        ttk.Label(
            self,
            text=(
                "Bước 4 (CRL) + Bước 5 (OCSP) gọi tới Prod CRL/OCSP server "
                "ở port 8889/8888 — đã tự khởi động cùng app."
            ),
            foreground="#888", font=font("caption"),
            padding=(12, 0, 12, 8), wraplength=740, justify=tk.LEFT,
        ).pack(anchor="w")

        # Log chi tiết 5 bước — stream realtime để thấy RÕ message lỗi của từng
        # bước. KHÔNG có khung "duyệt thành công/thất bại"; chỉ MỘT dòng tổng kết
        # PASS/FAIL ở cuối log.
        self.log_text = tk.Text(self, font=font("mono"), wrap=tk.WORD)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 12))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        self.log_text.tag_config("ok",   foreground=COLOR["success"])
        self.log_text.tag_config("fail", foreground=COLOR["danger"])
        self.log_text.tag_config("info", foreground=COLOR["text"])
        self.log_text.tag_config("head", foreground=COLOR["primary"],
                                 font=font("label"))
        self._log('Nhập hostname rồi bấm "Chạy 5 bước" để xác thực.', "info")

    def _log(self, msg: str, tag: str = "info") -> None:
        # Tự tô màu dòng PASS/FAIL trong log stream để lỗi hiện rõ.
        if tag == "info":
            if "[FAIL]" in msg:
                tag = "fail"
            elif "[PASS]" in msg:
                tag = "ok"
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def _run(self) -> None:
        hostname = self.host_entry.get().strip()
        if not hostname:
            messagebox.showerror("Lỗi", "Hostname không được rỗng.")
            return

        # Đảm bảo trust store có Root CA cert (best-effort).
        try:
            publish_active_to_trust_store(self.app.db_path, TRUST_STORE_DIR)
        except Exception:
            pass

        self.log_text.delete("1.0", tk.END)

        if not os.path.isdir(TRUST_STORE_DIR):
            self._log(
                "[FAIL] Trust Store chưa tồn tại — Admin cần tạo Root CA "
                "trước khi verify.", "fail",
            )
            return

        self._log(
            f"Verify external cert #{self.cert_rec['id']} — hostname '{hostname}'",
            "head",
        )
        self._log("===== BẮT ĐẦU 5 BƯỚC XÁC THỰC =====", "head")

        from core.verify import verify_certificate_full
        try:
            overall, results, _ = verify_certificate_full(
                bytes(self.cert_rec["cert_pem"]),
                hostname=hostname,
                trust_store_dir=TRUST_STORE_DIR,
                log_callback=self._log,
            )
        except Exception as e:
            self._log(f"[FAIL] Lỗi verify: {type(e).__name__}: {e}", "fail")
            return

        # MỘT dòng tổng kết duy nhất ở cuối log (không có khung banner).
        self._log("")
        if overall:
            self._log(
                "[PASS] Tổng kết: chứng chỉ HỢP LỆ (qua tất cả các bước).", "ok")
        else:
            # results chỉ gồm 5 bước chính (Bước 1-5) — liệt kê các bước đã fail.
            fails = [name for name, ok, _ in results if not ok]
            self._log(
                f"[FAIL] Tổng kết: chứng chỉ KHÔNG HỢP LỆ — thất bại ở: "
                f"{', '.join(fails) or '?'}.", "fail",
            )
