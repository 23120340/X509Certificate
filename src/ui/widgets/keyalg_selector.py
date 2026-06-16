"""
ui/widgets/keyalg_selector.py
-----------------------------
Bộ chọn thuật toán khóa kiểu CASCADING, dùng CHUNG cho cả "Sinh Root CA mới"
và "Cấu hình hệ thống" → hai nơi luôn ĐỒNG BỘ logic (một nguồn duy nhất).

    Loại khóa (RSA / ECDSA / Ed25519)
        → key size (RSA) / đường cong (ECDSA) / (Ed25519 không cần)
        → hàm băm phù hợp (tùy chọn; Ed25519 = cố định bên trong → khóa ô)

API:
  get_spec()      → 'RSA-2048' | 'RSA-3072' | 'RSA-4096' | 'EC-P256' | 'EC-P384'
                    | 'Ed25519'   (khớp core.keyalg.ALGO_CHOICES)
  get_hash_name() → 'SHA-256'/'SHA-384'/'SHA-512' hoặc None (Ed25519 hoặc
                    khi show_hash=False)
  set_spec(spec)  → prefill loại khóa + size/curve từ spec (int RSA-bit cũng OK)
  set_hash(name)  → prefill hàm băm ('SHA256' / 'SHA-256' / …)
  type_var/param_var → để caller đọc trực tiếp khi cần lưu config theo cột.
"""

import tkinter as tk
from tkinter import ttk


RSA_SIZES = ("2048", "3072", "4096")
EC_CURVES = ("P-256", "P-384")
HASHES    = ("SHA-256", "SHA-384", "SHA-512")
_HASH_DISPLAY = {"SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512"}
_ED_HASH_LABEL = "(cố định trong Ed25519)"

# Ràng buộc CỨNG hàm băm theo đường cong ECDSA: độ mạnh hash phải >= độ mạnh
# đường cong (NIST SP 800-57 / RFC 5480 / CNSA). P-384 (~192-bit) nên LOẠI
# SHA-256 (~128-bit) để hàm băm không thành "mắt xích yếu". Hash mạnh hơn thì OK.
_EC_ALLOWED_HASHES = {
    "P-256": ("SHA-256", "SHA-384", "SHA-512"),
    "P-384": ("SHA-384", "SHA-512"),
}


def spec_from(algorithm: str, key_size, ec_curve: str) -> str:
    """(algorithm, key_size, ec_curve) → spec string cho keyalg.generate_key."""
    a = (algorithm or "RSA").upper()
    if a.startswith("RSA"):
        size = str(key_size or "2048")
        return f"RSA-{size if size in RSA_SIZES else '2048'}"
    if a in ("ECDSA", "EC"):
        c = str(ec_curve or "P-256").upper().replace("-", "")
        return "EC-P384" if "384" in c else "EC-P256"
    if a in ("ED25519", "EDDSA"):
        return "Ed25519"
    return "RSA-2048"


class KeyAlgSelector(ttk.Frame):
    """Cascading selector. Đặt vào parent qua grid/pack như một khối widget."""

    def __init__(self, parent, *, show_hash: bool = True,
                 default_spec: str = "RSA-2048", default_hash: str = "SHA-256",
                 **kw):
        super().__init__(parent, **kw)
        self.show_hash = show_hash
        self._default_hash = self._norm_hash(default_hash)

        ttk.Label(self, text="Loại khóa:").grid(
            row=0, column=0, sticky="e", pady=4, padx=(0, 8))
        self.type_var = tk.StringVar(value="RSA")
        tc = ttk.Combobox(
            self, textvariable=self.type_var,
            values=("RSA", "ECDSA", "Ed25519"), state="readonly", width=16)
        tc.grid(row=0, column=1, sticky="w", pady=4)
        tc.bind("<<ComboboxSelected>>", lambda e: self._on_type_change())

        self.param_label = ttk.Label(self, text="Key size:")
        self.param_label.grid(row=1, column=0, sticky="e", pady=4, padx=(0, 8))
        self.param_var = tk.StringVar()
        self.param_combo = ttk.Combobox(
            self, textvariable=self.param_var, state="readonly", width=16)
        self.param_combo.grid(row=1, column=1, sticky="w", pady=4)
        self.param_combo.bind("<<ComboboxSelected>>",
                              lambda e: self._on_param_change())

        if self.show_hash:
            self.hash_label = ttk.Label(self, text="Hàm băm:")
            self.hash_label.grid(row=2, column=0, sticky="e", pady=4, padx=(0, 8))
            self.hash_var = tk.StringVar()
            self.hash_combo = ttk.Combobox(
                self, textvariable=self.hash_var, state="readonly", width=16)
            self.hash_combo.grid(row=2, column=1, sticky="w", pady=4)

        self.set_spec(default_spec)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _norm_hash(self, name) -> str:
        key = str(name or "").upper().replace("-", "")
        return _HASH_DISPLAY.get(key, name if name in HASHES else "SHA-256")

    def _on_type_change(self) -> None:
        t = self.type_var.get()
        if t == "RSA":
            self.param_label.config(text="Key size:")
            self.param_combo.config(values=RSA_SIZES, state="readonly")
            if self.param_var.get() not in RSA_SIZES:
                self.param_var.set("2048")
            self._enable_hash(HASHES)        # RSA: mọi SHA đều hợp lệ
        elif t == "ECDSA":
            self.param_label.config(text="Đường cong:")
            self.param_combo.config(values=EC_CURVES, state="readonly")
            if self.param_var.get() not in EC_CURVES:
                self.param_var.set("P-256")
            self._apply_ec_hash()            # ECDSA: lọc hash theo đường cong
        else:   # Ed25519 — hàm băm cố định bên trong, không chọn
            self.param_label.config(text="(không cần key size)")
            self.param_combo.config(values=(), state="disabled")
            self.param_var.set("")
            if self.show_hash:
                self.hash_combo.config(values=(_ED_HASH_LABEL,),
                                       state="disabled")
                self.hash_var.set(_ED_HASH_LABEL)

    def _enable_hash(self, choices) -> None:
        if not self.show_hash:
            return
        self.hash_combo.config(values=choices, state="readonly")
        if self.hash_var.get() not in choices:
            # snap về hash mặc định nếu hợp lệ, ngược lại hash nhỏ nhất được phép
            self.hash_var.set(self._default_hash if self._default_hash in choices
                              else choices[0])

    def _apply_ec_hash(self) -> None:
        # RÀNG BUỘC CỨNG: chỉ cho chọn hàm băm có độ mạnh >= đường cong.
        # P-384 loại SHA-256; tự snap nếu lựa chọn hiện tại không còn hợp lệ.
        allowed = _EC_ALLOWED_HASHES.get(self.param_var.get(), HASHES)
        self._enable_hash(allowed)

    def _on_param_change(self) -> None:
        if self.type_var.get() == "ECDSA":
            self._apply_ec_hash()

    # ── public ──────────────────────────────────────────────────────────────

    def set_spec(self, spec) -> None:
        s = str(spec or "RSA-2048").upper()
        if s.startswith("RSA"):
            self.type_var.set("RSA")
            digits = "".join(c for c in s if c.isdigit())
            self.param_var.set(digits if digits in RSA_SIZES else "2048")
        elif "384" in s and ("EC" in s or "P384" in s.replace("-", "")):
            self.type_var.set("ECDSA")
            self.param_var.set("P-384")
        elif "256" in s and ("EC" in s or "P256" in s.replace("-", "")):
            self.type_var.set("ECDSA")
            self.param_var.set("P-256")
        elif "ED25519" in s or "EDDSA" in s:
            self.type_var.set("Ed25519")
        else:
            self.type_var.set("RSA")
            self.param_var.set("2048")
        self._on_type_change()

    def set_hash(self, name) -> None:
        self._default_hash = self._norm_hash(name)
        if self.show_hash and self.type_var.get() != "Ed25519":
            self.hash_var.set(self._default_hash)

    def get_spec(self) -> str:
        t = self.type_var.get()
        if t == "RSA":
            return f"RSA-{self.param_var.get()}"
        if t == "ECDSA":
            return "EC-P384" if self.param_var.get() == "P-384" else "EC-P256"
        return "Ed25519"

    def get_hash_name(self):
        if not self.show_hash or self.type_var.get() == "Ed25519":
            return None
        return self.hash_var.get()
