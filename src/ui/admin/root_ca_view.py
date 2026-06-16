"""
ui/admin/root_ca_view.py
------------------------
Quản lý Root CA — đáp ứng A.4 (sinh keypair) + A.5 (phát sinh Root cert).

Layout:
  Phần A — Root CA active hiện tại
    • Nếu chưa có:  banner "Chưa có Root CA — bấm nút bên dưới để sinh"
    • Nếu đã có:    bảng thông tin (CN, serial, hiệu lực, người tạo) + nút
                    "Publish ra Trust Store", "Sinh Root CA mới (rotate)"
  Phần B — Lịch sử (table)
    • Liệt kê các Root CA đã từng có (kể cả retired).

Modal "Sinh Root CA":
  - common_name (default = system_config.root_ca_common_name nếu có)
  - key_size (radio 2048/3072/4096)
  - validity_days (entry, default = system_config.root_ca_validity_days)
"""

import tkinter as tk
from tkinter import ttk, messagebox

from ui.theme import font
from ui.common import fmt_local
from ui.widgets.modal import fit_to_content
from services.audit import write_audit, Action
from services.ca_admin import (
    create_root_ca, get_active_root_ca, list_root_ca_history, CAError,
    publish_active_to_trust_store,
    get_active_root_ca_public_key_pem, get_active_root_ca_spki_sha256,
)
from services.cert_lifecycle import (
    reissue_all_under_active_ca, CertLifecycleError,
)
from services.system_config import get_config, get_int_config
from ui.widgets.keyalg_selector import KeyAlgSelector, spec_from
from config import TRUST_STORE_DIR


DEFAULT_ROOT_CA_CN = "X509 Demo Root CA"
DEFAULT_TRUST_STORE_DIR = TRUST_STORE_DIR


class RootCAFrame(ttk.Frame):
    """Frame xem/sinh Root CA."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent, padding=24)
        self.app = app

        ttk.Label(
            self, text="Root Certificate Authority",
            font=font("heading_lg"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            self,
            text=(
                "Root CA là gốc tin cậy của toàn hệ thống. Mỗi cert phát hành "
                "đều phải được Root CA ký. Private key của Root CA được "
                "encrypt-at-rest (AES-256-GCM) trước khi lưu vào DB."
            ),
            foreground="#666", wraplength=720, justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 16))

        self._active_section = ttk.Frame(self)
        self._active_section.pack(fill=tk.X, anchor="w")

        ttk.Label(
            self, text="Lịch sử Root CA",
            font=font("heading_md"),
        ).pack(anchor="w", pady=(20, 4))
        self._build_history_table()

        self.refresh()

    # ── Active section ────────────────────────────────────────────────────────

    def _render_active(self, ca: "dict | None") -> None:
        for child in self._active_section.winfo_children():
            child.destroy()

        if ca is None:
            box = ttk.LabelFrame(
                self._active_section,
                text="Chưa có Root CA active", padding=12,
            )
            box.pack(fill=tk.X)
            ttk.Label(
                box,
                text=(
                    "Hệ thống chưa có Root CA. Bấm nút bên dưới để sinh "
                    "keypair (RSA) + Root Certificate. Private key sẽ được "
                    "mã hóa AES-GCM trước khi lưu DB."
                ),
                wraplength=680, justify=tk.LEFT, foreground="#444",
            ).pack(anchor="w", pady=(0, 8))
            ttk.Button(
                box, text="🔑 Sinh Root CA",
                command=self.open_generate_dialog,
            ).pack(anchor="w")
            return

        box = ttk.LabelFrame(
            self._active_section,
            text=f"Root CA active — #{ca['id']}", padding=12,
        )
        box.pack(fill=tk.X)

        def row(label: str, value: str) -> None:
            ttk.Label(
                box, text=label, font=font("label"), width=20,
            ).grid(column=0, sticky="w", padx=(0, 8), pady=2)
            ttk.Label(box, text=value).grid(
                column=1, sticky="w", pady=2,
            )

        # grid layout
        _time_keys = {"not_valid_before", "not_valid_after", "created_at"}
        for i, (label, key) in enumerate([
            ("Common Name",         "common_name"),
            ("Serial (hex)",        "serial_hex"),
            ("Not Valid Before",    "not_valid_before"),
            ("Not Valid After",     "not_valid_after"),
            ("Created at",          "created_at"),
        ]):
            ttk.Label(
                box, text=label, font=font("label"),
            ).grid(row=i, column=0, sticky="w", padx=(0, 12), pady=2)
            value = fmt_local(ca[key]) if key in _time_keys else str(ca[key])
            ttk.Label(box, text=value).grid(
                row=i, column=1, sticky="w", pady=2,
            )

        # Public key fingerprint — surface phần công khai của Root CA ngay
        # trên dashboard (xem chi tiết / export qua nút bên dưới).
        spki = get_active_root_ca_spki_sha256(self.app.db_path)
        ttk.Label(
            box, text="SPKI SHA-256", font=font("label"),
        ).grid(row=5, column=0, sticky="nw", padx=(0, 12), pady=2)
        ttk.Label(
            box, text=spki or "—", font=font("mono"),
            wraplength=520, justify="left",
        ).grid(row=5, column=1, sticky="w", pady=2)

        btn_row = ttk.Frame(box)
        btn_row.grid(row=99, column=0, columnspan=2, sticky="w", pady=(12, 0))
        ttk.Button(
            btn_row, text="🔑 Xem / Export Public Key",
            command=self.on_view_public_key,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            btn_row, text="📁 Publish ra Trust Store",
            command=self.on_publish,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            btn_row, text="♻ Cấp lại toàn bộ cert",
            command=self.on_reissue_all,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            btn_row, text="🔄 Sinh Root CA mới (rotate)",
            command=self.open_generate_dialog,
        ).pack(side=tk.LEFT)

    # ── History table ─────────────────────────────────────────────────────────

    def _build_history_table(self) -> None:
        cols = ("id", "common_name", "serial", "not_valid_after",
                "created_at", "is_active")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=6)
        labels = {
            "id": "ID", "common_name": "Common Name",
            "serial": "Serial", "not_valid_after": "Hết hạn",
            "created_at": "Tạo lúc", "is_active": "Active",
        }
        widths = {"id": 40, "common_name": 200, "serial": 220,
                  "not_valid_after": 170, "created_at": 170, "is_active": 60}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.pack(fill=tk.X)

    def refresh(self) -> None:
        ca = get_active_root_ca(self.app.db_path)
        self._render_active(ca)

        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for r in list_root_ca_history(self.app.db_path):
            self.tree.insert(
                "", tk.END,
                values=(
                    r["id"], r["common_name"], r["serial_hex"],
                    fmt_local(r["not_valid_after"]),
                    fmt_local(r["created_at"]),
                    "✓" if r["is_active"] else "",
                ),
            )

    # ── Actions ───────────────────────────────────────────────────────────────

    def open_generate_dialog(self) -> None:
        GenerateRootCADialog(self, self.app, on_done=self.refresh)

    def on_view_public_key(self) -> None:
        if get_active_root_ca(self.app.db_path) is None:
            messagebox.showwarning("Chưa có Root CA", "Sinh Root CA trước.")
            return
        ViewRootCAPublicKeyDialog(self, self.app)

    def on_reissue_all(self) -> None:
        if get_active_root_ca(self.app.db_path) is None:
            messagebox.showwarning("Chưa có Root CA", "Sinh Root CA trước.")
            return
        if not messagebox.askyesno(
            "Cấp lại toàn bộ cert",
            "Ký lại tất cả chứng chỉ đang còn hiệu lực bằng Root CA active "
            "hiện tại, thu hồi bản cũ và publish CRL mới?\n\n"
            "Cert đã do CA active ký sẽ được bỏ qua (idempotent).",
        ):
            return
        try:
            result = reissue_all_under_active_ca(
                admin_id=self.app.session["id"], db_path=self.app.db_path,
            )
        except CertLifecycleError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        write_audit(
            self.app.db_path, self.app.session["id"], Action.CA_REISSUE_ALL,
            target_type="root_ca", target_id="active",
            details={k: result[k]
                     for k in ("total", "reissued", "revoked", "skipped")},
        )
        messagebox.showinfo(
            "Hoàn tất",
            f"Đã cấp lại {result['reissued']} cert dưới Root CA active.\n"
            f"  • Thu hồi bản cũ: {result['revoked']}\n"
            f"  • Bỏ qua (đã do CA active ký): {result['skipped']}\n"
            f"  • Tổng cert active đã duyệt: {result['total']}\n"
            + ("  • Đã publish CRL mới." if result['crl'] else ""),
        )
        self.refresh()

    def on_publish(self) -> None:
        try:
            path = publish_active_to_trust_store(
                self.app.db_path, DEFAULT_TRUST_STORE_DIR,
            )
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            return
        if path:
            write_audit(
                self.app.db_path, self.app.session["id"],
                Action.TRUST_STORE_PUBLISHED,
                target_type="root_ca", target_id="active",
                details={"path": path},
            )
            messagebox.showinfo(
                "Đã publish",
                f"Đã ghi Root CA cert ra:\n{path}\n\n"
                f"Client/CRL server load file này để verify cert + CRL.",
            )
        else:
            messagebox.showwarning("Chưa có Root CA", "Sinh Root CA trước.")


class GenerateRootCADialog(tk.Toplevel):
    """Modal sinh Root CA mới (lần đầu hoặc rotate)."""

    def __init__(self, parent: tk.Misc, app, on_done=None):
        super().__init__(parent)
        self.app = app
        self.on_done = on_done

        self.title("Sinh Root CA mới")
        self.geometry("470x400")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Lấy default từ system_config (đồng bộ với "Cấu hình hệ thống").
        default_cn = get_config("root_ca_common_name", app.db_path) or DEFAULT_ROOT_CA_CN
        default_validity = get_int_config("root_ca_validity_days", app.db_path, 3650)
        default_spec = spec_from(
            get_config("default_key_algorithm", app.db_path) or "RSA",
            get_int_config("default_key_size", app.db_path, 2048),
            get_config("default_ec_curve", app.db_path) or "P-256",
        )
        default_hash = get_config("hash_algorithm", app.db_path) or "SHA256"

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Common Name:").grid(
            row=0, column=0, sticky="e", pady=6, padx=4
        )
        self.cn_entry = ttk.Entry(frame, width=30)
        self.cn_entry.grid(row=0, column=1, pady=6, padx=4, sticky="ew")
        self.cn_entry.insert(0, default_cn)

        # Bộ chọn khóa cascading — DÙNG CHUNG widget với "Cấu hình hệ thống"
        # (loại khóa → key size/đường cong → hàm băm phù hợp). Prefill từ config.
        self.keyalg = KeyAlgSelector(
            frame, show_hash=True,
            default_spec=default_spec, default_hash=default_hash,
        )
        self.keyalg.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        ttk.Label(frame, text="Validity (ngày):").grid(
            row=2, column=0, sticky="e", pady=6, padx=4
        )
        self.validity_entry = ttk.Entry(frame, width=12)
        self.validity_entry.grid(row=2, column=1, pady=6, padx=4, sticky="w")
        self.validity_entry.insert(0, str(default_validity))

        # Warning rotate
        has_active = get_active_root_ca(app.db_path) is not None
        if has_active:
            warn = ttk.Label(
                frame,
                text=(
                    "⚠ Hệ thống đã có Root CA active. Sinh Root CA mới sẽ "
                    "deactivate Root CA hiện tại. Các cert đã phát hành "
                    "vẫn còn chữ ký của Root CA cũ — client sẽ FAIL verify "
                    "cho đến khi bạn re-issue cert mới."
                ),
                foreground="#c0392b", wraplength=400, justify=tk.LEFT,
            )
            warn.grid(row=3, column=0, columnspan=2, sticky="w",
                      pady=(12, 0), padx=4)

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=99, column=0, columnspan=2, pady=(16, 0), sticky="e")
        ttk.Button(btn_row, text="Sinh", command=self.on_submit).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(btn_row, text="Hủy", command=self.destroy).pack(
            side=tk.RIGHT, padx=4
        )

        frame.columnconfigure(1, weight=1)
        self.cn_entry.focus_set()
        fit_to_content(self)

    def on_submit(self) -> None:
        cn = self.cn_entry.get().strip()
        try:
            validity = int(self.validity_entry.get())
        except ValueError:
            messagebox.showerror("Lỗi", "Validity phải là số nguyên.")
            return

        spec = self.keyalg.get_spec()
        hash_name = self.keyalg.get_hash_name()

        try:
            ca = create_root_ca(
                common_name=cn, key_size=2048, validity_days=validity,
                created_by=self.app.session["id"], db_path=self.app.db_path,
                algorithm=spec, hash_name=hash_name,
            )
        except CAError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        except Exception as e:
            messagebox.showerror("Lỗi không lường", f"{type(e).__name__}: {e}")
            return

        action = (Action.ROOT_CA_ROTATED if ca["id"] > 1
                  else Action.ROOT_CA_CREATED)
        write_audit(
            self.app.db_path, self.app.session["id"], action,
            target_type="root_ca", target_id=str(ca["id"]),
            details={
                "common_name":  ca["common_name"],
                "serial_hex":   ca["serial_hex"],
                "algorithm":    ca["algorithm"],
                "key_size":     ca["key_size"],
                "hash":         hash_name or "fixed(Ed25519)",
                "validity_days": validity,
            },
        )

        _algo_disp = ca["algorithm"] + (f"-{ca['key_size']}"
                                        if ca["key_size"] else "")
        messagebox.showinfo(
            "Thành công",
            f"Đã sinh Root CA mới (#{ca['id']}).\n"
            f"CN: {ca['common_name']}\n"
            f"Thuật toán: {_algo_disp}\n"
            f"Serial: {ca['serial_hex']}\n"
            f"Hết hạn: {fmt_local(ca['not_valid_after'])}",
        )
        if self.on_done:
            self.on_done()
        self.destroy()


class ViewRootCAPublicKeyDialog(tk.Toplevel):
    """Hiển thị + export PUBLIC KEY của Root CA active (phần công khai)."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent)
        self.app = app
        self.title("Root CA — Public Key")
        self.geometry("700x480")
        self.transient(parent)
        self.grab_set()

        pem = get_active_root_ca_public_key_pem(app.db_path)
        spki = get_active_root_ca_spki_sha256(app.db_path)
        self._pem_str = (
            bytes(pem).decode("ascii", errors="replace").strip() if pem else ""
        )

        ttk.Label(
            self,
            text=(
                "Public key (SubjectPublicKeyInfo) của Root CA active. Đây là "
                "phần CÔNG KHAI — có thể chia sẻ cho client/đối tác để verify "
                "chữ ký chứng chỉ và CRL. Private key KHÔNG bao giờ xuất ra."
            ),
            wraplength=660, foreground="#666", justify=tk.LEFT, padding=(12, 8),
        ).pack(anchor="w")

        fp_row = ttk.Frame(self)
        fp_row.pack(anchor="w", fill=tk.X, padx=12)
        ttk.Label(fp_row, text="SPKI SHA-256:", font=font("label")).pack(side=tk.LEFT)
        ttk.Label(fp_row, text=spki or "—", font=font("mono"),
                  wraplength=560, justify=tk.LEFT).pack(side=tk.LEFT, padx=(6, 0))

        text = tk.Text(self, font=font("mono"), wrap=tk.NONE, height=14)
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(8, 12))
        text.insert("1.0", self._pem_str)
        text.config(state=tk.DISABLED)

        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(btn_row, text="Copy", command=self._on_copy).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Save As…", command=self._on_save).pack(
            side=tk.LEFT, padx=(8, 0))
        ttk.Button(btn_row, text="Đóng", command=self.destroy).pack(side=tk.RIGHT)
        fit_to_content(self)

    def _on_copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._pem_str)

    def _on_save(self) -> None:
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Lưu Root CA public key",
            defaultextension=".pem",
            initialfile="root-ca-public-key.pem",
            filetypes=(("PEM public key", "*.pem *.pub"), ("All files", "*.*")),
        )
        if not path:
            return
        with open(path, "w", encoding="ascii") as f:
            f.write(self._pem_str + "\n")
        write_audit(
            self.app.db_path, self.app.session["id"],
            Action.ROOT_CA_PUBKEY_EXPORTED,
            target_type="root_ca", target_id="active",
            details={"path": path},
        )
        messagebox.showinfo("Đã lưu", f"Đã lưu public key vào:\n{path}")
