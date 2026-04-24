"""
gui.py
------
Phần 6 của đề bài: Giao diện Tkinter.

  - Các nút: Generate Certificate, Start CRL, Start OCSP, Start Server, Connect Client.
  - Radio chọn kịch bản: Valid / Expired / Revoked.
  - Khu vực hiển thị thông tin chứng chỉ chi tiết.
  - Log quá trình xác thực từng bước.
  - Kết quả cuối cùng: PASS (xanh) / FAIL (đỏ).
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime

from cert_generator import (
    generate_rsa_keypair,
    create_self_signed_cert,
    save_cert_and_key,
)
from crl_manager import build_crl, save_crl, save_revoked_list
from server import start_cert_server
from ocsp_server import start_ocsp_server
from crl_server import start_crl_server
from client import fetch_certificate, verify_certificate_full


# ---- Cấu hình đường dẫn & cổng ----
CERT_DIR = "certs"
CERT_PATH = os.path.join(CERT_DIR, "server.crt")
KEY_PATH = os.path.join(CERT_DIR, "server.key")
CRL_PATH = os.path.join(CERT_DIR, "crl.pem")
REVOKED_PATH = os.path.join(CERT_DIR, "revoked_serials.json")

SERVER_HOST = "localhost"
SERVER_PORT = 9999
OCSP_PORT = 8888
CRL_PORT = 8889


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("X.509 v3 Self-Signed Certificate Simulator")
        root.geometry("1180x780")
        root.minsize(900, 650)

        self.current_serial = None
        self.server_started = False
        self.ocsp_started = False
        self.crl_started = False

        os.makedirs(CERT_DIR, exist_ok=True)
        self._build_ui()

    # ------------------------------------------------------------------ UI --
    def _build_ui(self):
        # Style
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # -- Top control bar --
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        # Scenario selector
        scenario_box = ttk.LabelFrame(top, text="Kịch bản kiểm thử", padding=8)
        scenario_box.pack(side=tk.LEFT, padx=5, fill=tk.Y)

        self.scenario_var = tk.StringVar(value="valid")
        ttk.Radiobutton(
            scenario_box, text="1. Chứng chỉ hợp lệ (kỳ vọng PASS)",
            variable=self.scenario_var, value="valid",
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            scenario_box, text="2. Chứng chỉ hết hạn (kỳ vọng FAIL)",
            variable=self.scenario_var, value="expired",
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            scenario_box, text="3. Chứng chỉ bị thu hồi (kỳ vọng FAIL)",
            variable=self.scenario_var, value="revoked",
        ).pack(anchor=tk.W)

        # Buttons
        btn_box = ttk.LabelFrame(top, text="Chức năng", padding=8)
        btn_box.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)

        self.btn_gen = ttk.Button(
            btn_box, text="① Generate Certificate", command=self.on_generate
        )
        self.btn_crl = ttk.Button(
            btn_box, text="② Start CRL Server", command=self.on_start_crl
        )
        self.btn_ocsp = ttk.Button(
            btn_box, text="③ Start OCSP Server", command=self.on_start_ocsp
        )
        self.btn_srv = ttk.Button(
            btn_box, text="④ Start Server", command=self.on_start_server
        )
        self.btn_cli = ttk.Button(
            btn_box, text="⑤ Connect Client & Verify", command=self.on_connect_client
        )
        self.btn_clr = ttk.Button(
            btn_box, text="Clear Log", command=self.on_clear_log
        )

        self.btn_gen.grid(row=0, column=0, padx=3, pady=3, sticky="ew")
        self.btn_crl.grid(row=0, column=1, padx=3, pady=3, sticky="ew")
        self.btn_ocsp.grid(row=0, column=2, padx=3, pady=3, sticky="ew")
        self.btn_srv.grid(row=1, column=0, padx=3, pady=3, sticky="ew")
        self.btn_cli.grid(row=1, column=1, padx=3, pady=3, sticky="ew")
        self.btn_clr.grid(row=1, column=2, padx=3, pady=3, sticky="ew")
        for c in range(3):
            btn_box.columnconfigure(c, weight=1)

        # -- Middle: cert info (left) + log (right) --
        mid = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        mid.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(mid, text="Thông tin chứng chỉ", padding=5)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        self.cert_info = scrolledtext.ScrolledText(
            left, height=22, font=("Courier New", 9), wrap=tk.WORD
        )
        self.cert_info.pack(fill=tk.BOTH, expand=True)

        right = ttk.LabelFrame(mid, text="Log quá trình (step-by-step)", padding=5)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self.log_text = scrolledtext.ScrolledText(
            right, height=22, font=("Courier New", 9), wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        # Color tags
        self.log_text.tag_config("ok", foreground="#1e8449")
        self.log_text.tag_config("fail", foreground="#c0392b")
        self.log_text.tag_config("info", foreground="#2c3e50")
        self.log_text.tag_config("head", foreground="#2471a3", font=("Courier New", 9, "bold"))

        # -- Result banner --
        self.result_frame = tk.Frame(self.root, height=70, bg="#95a5a6")
        self.result_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.result_frame.pack_propagate(False)

        self.result_label = tk.Label(
            self.result_frame,
            text="Chưa chạy xác thực",
            bg="#95a5a6", fg="white",
            font=("Arial", 20, "bold"),
        )
        self.result_label.pack(expand=True, fill=tk.BOTH)

    # --------------------------------------------------------------- Logging
    def log(self, msg: str, tag: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def _thread_log(self, msg: str):
        """Log an lưu tiện gọi từ thread khác (Tkinter không thread-safe tuyệt đối,
        nhưng insert/see thường OK; dùng after để an toàn hơn)."""
        self.root.after(0, self.log, msg)

    def set_result(self, status: str):
        """status: 'pass' | 'fail' | 'reset'"""
        if status == "pass":
            color, text = "#27ae60", "✓  PASS - CHỨNG CHỈ HỢP LỆ"
        elif status == "fail":
            color, text = "#c0392b", "✗  FAIL - CHỨNG CHỈ KHÔNG HỢP LỆ"
        else:
            color, text = "#95a5a6", "Chưa chạy xác thực"
        self.result_frame.config(bg=color)
        self.result_label.config(bg=color, text=text)

    # ----------------------------------------------------------- Button cbs
    def on_clear_log(self):
        self.log_text.delete("1.0", tk.END)
        self.cert_info.delete("1.0", tk.END)
        self.set_result("reset")

    def on_generate(self):
        scenario = self.scenario_var.get()
        self.log(f"► Sinh chứng chỉ cho kịch bản: {scenario.upper()}", "head")
        try:
            priv = generate_rsa_keypair()
            self.log("  ✓ Đã sinh cặp khóa RSA 2048-bit", "ok")

            expired = (scenario == "expired")
            cert, serial = create_self_signed_cert(
                priv,
                common_name="localhost",
                dns_names=["localhost", "127.0.0.1"],
                ocsp_url=f"http://localhost:{OCSP_PORT}/ocsp",
                crl_url=f"http://localhost:{CRL_PORT}/crl.pem",
                expired=expired,
            )
            self.log(f"  ✓ Đã tạo chứng chỉ X.509 v3 (serial = {serial})", "ok")

            save_cert_and_key(cert, priv, CERT_PATH, KEY_PATH)
            self.log(f"  ✓ Đã lưu: {CERT_PATH} và {KEY_PATH}", "ok")

            self.current_serial = serial

            # Tạo CRL theo kịch bản
            revoked = [serial] if scenario == "revoked" else []
            crl = build_crl(cert, priv, revoked)
            save_crl(crl, CRL_PATH)
            save_revoked_list(revoked, REVOKED_PATH)
            self.log(
                f"  ✓ Đã sinh CRL ({len(revoked)} serial bị thu hồi) và "
                f"revoked_serials.json",
                "ok",
            )

            self._display_cert_info(cert)
        except Exception as e:
            self.log(f"  ✗ LỖI: {e}", "fail")
            import traceback
            traceback.print_exc()

    def _display_cert_info(self, cert):
        lines = []
        lines.append(f"Version          : {cert.version.name}")
        lines.append(f"Serial Number    : {cert.serial_number}")
        lines.append(f"Signature Algo   : {cert.signature_algorithm_oid._name}")
        lines.append(f"Issuer           : {cert.issuer.rfc4514_string()}")
        lines.append(f"Subject          : {cert.subject.rfc4514_string()}")
        try:
            nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        except AttributeError:
            nb, na = cert.not_valid_before, cert.not_valid_after
        lines.append(f"Not Before       : {nb}")
        lines.append(f"Not After        : {na}")

        pub = cert.public_key()
        lines.append(f"Public Key       : RSA {pub.key_size} bits")

        lines.append("")
        lines.append("=== X.509 v3 Extensions ===")
        for ext in cert.extensions:
            lines.append(f"• {ext.oid._name}  (critical={ext.critical})")
            lines.append(f"    {ext.value}")
            lines.append("")

        self.cert_info.delete("1.0", tk.END)
        self.cert_info.insert(tk.END, "\n".join(lines))

    def on_start_crl(self):
        if self.crl_started:
            self.log("[CRL]  Đã chạy rồi, bỏ qua.", "info")
            return
        try:
            start_crl_server(
                host="localhost", port=CRL_PORT,
                crl_path=CRL_PATH, log_callback=self._thread_log,
            )
            self.crl_started = True
        except Exception as e:
            self.log(f"[CRL]  LỖI khi start: {e}", "fail")

    def on_start_ocsp(self):
        if self.ocsp_started:
            self.log("[OCSP] Đã chạy rồi, bỏ qua.", "info")
            return
        try:
            start_ocsp_server(
                host="localhost", port=OCSP_PORT,
                revoked_list_path=REVOKED_PATH, log_callback=self._thread_log,
            )
            self.ocsp_started = True
        except Exception as e:
            self.log(f"[OCSP] LỖI khi start: {e}", "fail")

    def on_start_server(self):
        if not os.path.exists(CERT_PATH):
            messagebox.showwarning(
                "Chưa có chứng chỉ",
                "Bạn cần bấm ① Generate Certificate trước khi start server.",
            )
            return
        if self.server_started:
            self.log("[Server] Đã chạy rồi, bỏ qua.", "info")
            return
        try:
            start_cert_server(
                CERT_PATH, host=SERVER_HOST, port=SERVER_PORT,
                log_callback=self._thread_log,
            )
            self.server_started = True
        except Exception as e:
            self.log(f"[Server] LỖI khi start: {e}", "fail")

    def on_connect_client(self):
        if not self.server_started:
            messagebox.showwarning(
                "Chưa start server",
                "Hãy start đủ các server (CRL, OCSP, Socket) trước khi verify.",
            )
            return
        threading.Thread(target=self._do_verify, daemon=True).start()

    def _do_verify(self):
        try:
            self._thread_log("► Client kết nối Socket server để lấy certificate...")
            cert_bytes = fetch_certificate(SERVER_HOST, SERVER_PORT)
            self._thread_log(f"  ✓ Đã nhận {len(cert_bytes)} bytes PEM từ server.")
            self._thread_log("")
            self._thread_log("╔══════ BẮT ĐẦU QUY TRÌNH XÁC THỰC 5 BƯỚC ══════╗")

            overall, results, _ = verify_certificate_full(
                cert_bytes, SERVER_HOST, log_callback=self._thread_log
            )

            self._thread_log("╚══════════════ KẾT QUẢ TỔNG HỢP ══════════════╝")
            for name, ok, _msg in results:
                tag = "PASS" if ok else "FAIL"
                self._thread_log(f"   [{tag}] {name}")

            self.root.after(0, self.set_result, "pass" if overall else "fail")
        except Exception as e:
            self._thread_log(f"  ✗ LỖI verify: {e}")
            import traceback
            traceback.print_exc()
            self.root.after(0, self.set_result, "fail")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
