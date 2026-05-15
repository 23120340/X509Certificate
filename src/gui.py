"""
gui.py
------
Dynamic Multi-Server X.509 Demo — Tkinter GUI.

Layout:
  [Cơ sở hạ tầng]  [Thêm Server mới]
  [Danh sách Server đang chạy — Treeview]
  [Thông tin cert] | [Log step-by-step]
  [Banner PASS/FAIL]
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime

from cryptography import x509

from issuer import load_or_create_issuer, publish_root_ca_to_trust_store
from server_manager import ServerManager, FLAVORS
from crl_manager import build_and_publish_crl
from ocsp_server import OCSPHandler, start_ocsp_server
from crl_server import start_crl_server
from client import fetch_certificate, verify_certificate_full

# ── Đường dẫn và cổng mặc định ───────────────────────────────────────────────
CERT_DIR        = "certs"
ISSUER_CERT     = os.path.join(CERT_DIR, "issuer.crt")
ISSUER_KEY      = os.path.join(CERT_DIR, "issuer.key")
CRL_PATH        = os.path.join(CERT_DIR, "crl.pem")
OCSP_DB_PATH    = os.path.join(CERT_DIR, "ocsp_db.json")
TRUST_STORE_DIR = os.path.join(CERT_DIR, "trust_store")

OCSP_PORT = 8888
CRL_PORT  = 8889
OCSP_URL  = f"http://localhost:{OCSP_PORT}/ocsp"
CRL_URL   = f"http://localhost:{CRL_PORT}/crl.pem"

FLAVOR_LABELS = {
    "valid":             "valid — cert hợp lệ",
    "expired":           "expired — cert hết hạn",
    "revoked_both":      "revoked_both — CRL + OCSP đều biết",
    "revoked_ocsp_only": "revoked_ocsp_only — chỉ OCSP biết (CRL chưa publish)",
    "tampered":          "tampered — cert bị sửa 1 bit",
}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("X.509 Dynamic Multi-Server Demo")
        root.geometry("1280x860")
        root.minsize(1000, 720)

        self.crl_started  = False
        self.ocsp_started = False
        self.ocsp_enabled_var = tk.BooleanVar(value=True)

        os.makedirs(CERT_DIR, exist_ok=True)

        # Tạo Root CA (issuer): ký server cert + ký CRL
        self.issuer_cert, self.issuer_key = load_or_create_issuer(ISSUER_CERT, ISSUER_KEY)

        # Publish Root CA vào Trust Store để client load khi verify
        self.trust_store_dir = TRUST_STORE_DIR
        publish_root_ca_to_trust_store(self.issuer_cert, self.trust_store_dir)

        # Khởi tạo ServerManager
        self.mgr = ServerManager(
            cert_dir=CERT_DIR,
            ocsp_db_path=OCSP_DB_PATH,
            crl_path=CRL_PATH,
            issuer_cert=self.issuer_cert,
            issuer_key=self.issuer_key,
            ocsp_url=OCSP_URL,
            crl_url=CRL_URL,
            log_callback=self._thread_log,
        )

        self._build_ui()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Xây dựng giao diện ───────────────────────────────────────────────────

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # ── Hàng trên: Hạ tầng + Thêm server ────────────────────────────────
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.X)

        self._build_infra_panel(top)
        self._build_add_server_panel(top)

        # ── Danh sách server (Treeview) ───────────────────────────────────────
        self._build_server_list(self.root)

        # ── Cert info + Log ───────────────────────────────────────────────────
        mid = ttk.Frame(self.root, padding=(8, 0, 8, 0))
        mid.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(mid, text="Thông tin chứng chỉ", padding=4)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))
        self.cert_info = scrolledtext.ScrolledText(
            left, height=14, font=("Courier New", 8), wrap=tk.WORD
        )
        self.cert_info.pack(fill=tk.BOTH, expand=True)

        right = ttk.LabelFrame(mid, text="Log quá trình (step-by-step)", padding=4)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))
        self.log_text = scrolledtext.ScrolledText(
            right, height=14, font=("Courier New", 8), wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_config("ok",   foreground="#1e8449")
        self.log_text.tag_config("fail", foreground="#c0392b")
        self.log_text.tag_config("info", foreground="#2c3e50")
        self.log_text.tag_config("head", foreground="#2471a3",
                                 font=("Courier New", 8, "bold"))

        # ── Banner kết quả ────────────────────────────────────────────────────
        self.result_frame = tk.Frame(self.root, height=60, bg="#95a5a6")
        self.result_frame.pack(fill=tk.X, padx=8, pady=(4, 8))
        self.result_frame.pack_propagate(False)
        self.result_label = tk.Label(
            self.result_frame, text="Chưa chạy xác thực",
            bg="#95a5a6", fg="white", font=("Arial", 18, "bold"),
        )
        self.result_label.pack(expand=True, fill=tk.BOTH)

    def _build_infra_panel(self, parent):
        box = ttk.LabelFrame(parent, text="Cơ sở hạ tầng", padding=8)
        box.pack(side=tk.LEFT, padx=(0, 8), fill=tk.Y)

        ttk.Button(box, text="Start CRL Server",
                   command=self.on_start_crl).grid(row=0, column=0, padx=4, pady=3, sticky="ew")
        ttk.Button(box, text="Start OCSP Server",
                   command=self.on_start_ocsp).grid(row=0, column=1, padx=4, pady=3, sticky="ew")
        ttk.Button(box, text="📢 Publish CRL Now",
                   command=self.on_publish_crl).grid(row=1, column=0, padx=4, pady=3, sticky="ew")
        ttk.Button(box, text="Clear Log",
                   command=self.on_clear_log).grid(row=1, column=1, padx=4, pady=3, sticky="ew")

        chk = ttk.Checkbutton(
            box, text="OCSP Responder ENABLED",
            variable=self.ocsp_enabled_var,
            command=self.on_toggle_ocsp,
        )
        chk.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        box.columnconfigure(0, weight=1)
        box.columnconfigure(1, weight=1)

    def _build_add_server_panel(self, parent):
        box = ttk.LabelFrame(parent, text="Thêm Server mới", padding=8)
        box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(box, text="Tên:").grid(row=0, column=0, sticky="e", padx=4)
        self.entry_name = ttk.Entry(box, width=14)
        self.entry_name.grid(row=0, column=1, padx=4, pady=3, sticky="ew")
        self.entry_name.insert(0, "Server-A")

        ttk.Label(box, text="Port:").grid(row=0, column=2, sticky="e", padx=4)
        self.entry_port = ttk.Entry(box, width=7)
        self.entry_port.grid(row=0, column=3, padx=4, pady=3)
        self.entry_port.insert(0, "9001")

        ttk.Label(box, text="Loại cert:").grid(row=1, column=0, sticky="e", padx=4)
        self.combo_flavor = ttk.Combobox(
            box,
            values=list(FLAVOR_LABELS.values()),
            state="readonly",
            width=42,
        )
        self.combo_flavor.grid(row=1, column=1, columnspan=3, padx=4, pady=3, sticky="ew")
        self.combo_flavor.current(0)

        ttk.Button(box, text="➕ Thêm Server",
                   command=self.on_add_server).grid(
            row=2, column=0, columnspan=4, pady=(6, 2), sticky="ew", padx=4)

        for c in range(4):
            box.columnconfigure(c, weight=1 if c in (1, 3) else 0)

    def _build_server_list(self, parent):
        box = ttk.LabelFrame(parent, text="Danh sách Server đang chạy", padding=6)
        box.pack(fill=tk.X, padx=8, pady=(0, 4))

        # Treeview
        cols = ("name", "port", "flavor", "serial")
        self.tree = ttk.Treeview(box, columns=cols, show="headings", height=5)
        self.tree.heading("name",   text="Tên")
        self.tree.heading("port",   text="Port")
        self.tree.heading("flavor", text="Loại cert")
        self.tree.heading("serial", text="Serial (hex)")
        self.tree.column("name",   width=110, anchor="center")
        self.tree.column("port",   width=70,  anchor="center")
        self.tree.column("flavor", width=230, anchor="w")
        self.tree.column("serial", width=220, anchor="w")

        vsb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.LEFT, fill=tk.Y)

        # Nút hành động
        btn_frame = ttk.Frame(box)
        btn_frame.pack(side=tk.LEFT, padx=(8, 0), anchor="n")
        ttk.Button(btn_frame, text="🔍 Verify",
                   command=self.on_verify, width=16).pack(pady=3)
        ttk.Button(btn_frame, text="🗑 Xóa",
                   command=self.on_delete, width=16).pack(pady=3)
        ttk.Button(btn_frame, text="📋 Xem cert",
                   command=self.on_view_cert, width=16).pack(pady=3)

    # ── Logging & Banner ─────────────────────────────────────────────────────

    def log(self, msg: str, tag: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def _thread_log(self, msg: str):
        self.root.after(0, self.log, msg)

    def set_result(self, status: str):
        mapping = {
            "pass":  ("#27ae60", "✓  PASS — CHỨNG CHỈ HỢP LỆ"),
            "fail":  ("#c0392b", "✗  FAIL — CHỨNG CHỈ KHÔNG HỢP LỆ"),
            "reset": ("#95a5a6", "Chưa chạy xác thực"),
        }
        color, text = mapping.get(status, mapping["reset"])
        self.result_frame.config(bg=color)
        self.result_label.config(bg=color, text=text)

    def on_clear_log(self):
        self.log_text.delete("1.0", tk.END)
        self.cert_info.delete("1.0", tk.END)
        self.set_result("reset")

    # ── Hạ tầng ──────────────────────────────────────────────────────────────

    def on_start_crl(self):
        if self.crl_started:
            self.log("[CRL] Đã chạy rồi.", "info"); return
        try:
            start_crl_server(
                host="localhost", port=CRL_PORT,
                crl_path=CRL_PATH, log_callback=self._thread_log,
            )
            self.crl_started = True
        except Exception as e:
            self.log(f"[CRL] LỖI: {e}", "fail")

    def on_start_ocsp(self):
        if self.ocsp_started:
            self.log("[OCSP] Đã chạy rồi.", "info"); return
        try:
            start_ocsp_server(
                host="localhost", port=OCSP_PORT,
                revoked_list_path=OCSP_DB_PATH,
                log_callback=self._thread_log,
            )
            self.ocsp_started = True
        except Exception as e:
            self.log(f"[OCSP] LỖI: {e}", "fail")

    def on_publish_crl(self):
        """Snapshot OCSP DB → build CRL → ghi ra file."""
        try:
            crl = build_and_publish_crl(
                self.issuer_cert, self.issuer_key,
                OCSP_DB_PATH, CRL_PATH,
            )
            # Đếm số serial trong CRL vừa publish
            count = sum(1 for _ in crl)
            self.log(f"[CRL] Đã publish CRL — {count} serial bị thu hồi.", "ok")
        except Exception as e:
            self.log(f"[CRL] LỖI khi publish: {e}", "fail")

    def on_toggle_ocsp(self):
        enabled = self.ocsp_enabled_var.get()
        OCSPHandler.enabled = enabled
        state = "BẬT" if enabled else "TẮT"
        tag   = "ok" if enabled else "fail"
        self.log(f"[OCSP] Responder đã {state}.", tag)

    # ── Thêm / Xóa server ────────────────────────────────────────────────────

    def _parse_flavor_key(self) -> str:
        """Lấy flavor key từ combo box (ví dụ 'valid' từ 'valid — cert hợp lệ')."""
        label = self.combo_flavor.get()
        for key, lbl in FLAVOR_LABELS.items():
            if lbl == label:
                return key
        return list(FLAVOR_LABELS.keys())[0]

    def on_add_server(self):
        name   = self.entry_name.get().strip()
        flavor = self._parse_flavor_key()

        if not name:
            messagebox.showerror("Lỗi", "Tên server không được để trống.")
            return
        try:
            port = int(self.entry_port.get().strip())
            if not (1024 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Lỗi", "Port phải là số nguyên từ 1024 đến 65535.")
            return

        try:
            entry = self.mgr.add_server(name, port, flavor)
        except (ValueError, OSError) as e:
            messagebox.showerror("Lỗi", str(e))
            return

        self.tree.insert(
            "", tk.END, iid=name,
            values=(name, port, flavor, f"{entry.serial:#x}"),
        )
        self.log(f"[+] '{name}' port={port} flavor={flavor} serial={entry.serial:#x}", "ok")

        # Gợi ý port tiếp theo
        try:
            self.entry_port.delete(0, tk.END)
            self.entry_port.insert(0, str(port + 1))
        except Exception:
            pass

    def on_delete(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Hãy chọn server cần xóa trong bảng.")
            return
        name = sel[0]
        if not messagebox.askyesno("Xác nhận", f"Xóa server '{name}'?"):
            return
        self.mgr.remove_server(name)
        self.tree.delete(name)
        self.log(f"[-] Server '{name}' đã xóa.", "info")

    # ── Verify ────────────────────────────────────────────────────────────────

    def on_verify(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Hãy chọn server cần verify trong bảng.")
            return
        name  = sel[0]
        entry = self.mgr.servers.get(name)
        if entry is None:
            return
        self.set_result("reset")
        threading.Thread(target=self._do_verify, args=(entry,), daemon=True).start()

    def _do_verify(self, entry):
        host = "localhost"
        try:
            self._thread_log(
                f"► Verify '{entry.name}' (port={entry.port}, flavor={entry.flavor})"
            )
            cert_bytes, peer_address = fetch_certificate(host, entry.port)
            self._thread_log(
                f"  ✓ Nhận {len(cert_bytes)} bytes PEM từ server "
                f"(peer={peer_address})."
            )
            self._thread_log("")
            self._thread_log("╔══════ BẮT ĐẦU 5 BƯỚC XÁC THỰC ══════╗")

            overall, results, cert_obj = verify_certificate_full(
                cert_bytes, host,
                trust_store_dir=self.trust_store_dir,
                log_callback=self._thread_log,
                peer_address=peer_address,
            )

            self._thread_log("╚══════════════ KẾT QUẢ ══════════════╝")
            for step_name, ok, _ in results:
                self._thread_log(f"   [{'PASS' if ok else 'FAIL'}] {step_name}")

            self.root.after(0, self.set_result, "pass" if overall else "fail")
            self.root.after(0, self._display_cert, cert_obj, entry)

        except Exception as e:
            self._thread_log(f"  ✗ LỖI kết nối: {e}")
            self.root.after(0, self.set_result, "fail")

    # ── Xem cert ──────────────────────────────────────────────────────────────

    def on_view_cert(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Hãy chọn server trong bảng.")
            return
        name  = sel[0]
        entry = self.mgr.servers.get(name)
        if entry is None:
            return
        try:
            with open(entry.cert_path, "rb") as f:
                cert_pem = f.read()
            cert_obj = x509.load_pem_x509_certificate(cert_pem)
            self._display_cert(cert_obj, entry)
        except Exception as e:
            self.log(f"Lỗi xem cert '{name}': {e}", "fail")

    def _display_cert(self, cert, entry):
        """Hiển thị thông tin chi tiết cert vào panel bên trái."""
        lines = []
        lines.append(f"Server  : {entry.name}  (port {entry.port})")
        lines.append(f"Flavor  : {entry.flavor}")
        lines.append("")
        lines.append(f"Version          : {cert.version.name}")
        lines.append(f"Serial           : {cert.serial_number:#x}")
        lines.append(f"Signature Algo   : {cert.signature_algorithm_oid._name}")
        lines.append(f"Issuer           : {cert.issuer.rfc4514_string()}")
        lines.append(f"Subject          : {cert.subject.rfc4514_string()}")
        try:
            nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        except AttributeError:
            nb = cert.not_valid_before
            na = cert.not_valid_after
        lines.append(f"Not Before       : {nb}")
        lines.append(f"Not After        : {na}")
        lines.append(f"Public Key       : RSA {cert.public_key().key_size} bits")
        lines.append("")
        lines.append("=== Extensions ===")
        for ext in cert.extensions:
            lines.append(f"  • {ext.oid._name}  (critical={ext.critical})")
            lines.append(f"      {ext.value}")

        self.cert_info.delete("1.0", tk.END)
        self.cert_info.insert(tk.END, "\n".join(lines))

    # ── Đóng cửa sổ ──────────────────────────────────────────────────────────

    def _on_close(self):
        """
        Đóng app: chỉ dừng socket, KHÔNG xóa cert file. Mục đích là để lần
        khởi động sau, cert/key của các 'valid' server còn trên disk và
        ServerManager có thể reuse → pin warning của client ổn định qua
        các lần mở/đóng GUI.
        """
        self.mgr.remove_all(cleanup_files=False)
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
