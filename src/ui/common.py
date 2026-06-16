"""
ui/common.py
------------
Widget dùng chung cho cả admin và customer dashboard:
  • ChangePasswordDialog — modal dialog đổi mật khẩu (A.2 / B.3)
  • build_dashboard_header — header bar có user info + nút Đổi mật khẩu + Đăng xuất
  • coming_soon_frame — placeholder cho các tính năng chưa làm
"""

from datetime import datetime, timezone

import tkinter as tk
from tkinter import ttk, messagebox

from cryptography import x509

from services.auth import change_password, AuthError
from services.audit import write_audit, Action
from ui.theme import COLOR, SPACE, font
from ui.widgets.modal import fit_to_content


# ── Formatting helpers (dùng chung mọi view) ─────────────────────────────────
# Mọi mốc thời gian trong hệ thống được LƯU dạng ISO-8601 UTC (tz-aware). Khi
# HIỂN THỊ ta quy đổi sang giờ local của máy đang chạy + gắn nhãn múi giờ, để
# người dùng (vd UTC+7) không đọc nhầm giờ UTC thành giờ địa phương.

def fmt_local(value, *, with_seconds: bool = True, with_label: bool = True) -> str:
    """
    Format 1 mốc thời gian (ISO-8601 string hoặc datetime) sang giờ LOCAL.

      • None / "" / không parse được  → "—" (hoặc chuỗi gốc rút gọn)
      • ISO string '…+00:00'          → parse, đổi sang giờ local của máy
      • datetime naive                → coi như UTC
    Định dạng: 'YYYY-MM-DD HH:MM:SS (UTC+07:00)'.
    """
    if value is None or value == "":
        return "—"
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            s = str(value)
            return s[:19].replace("T", " ") if len(s) >= 10 else (s or "—")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone()  # đổi sang giờ local của máy client
    mask = "%Y-%m-%d %H:%M:%S" if with_seconds else "%Y-%m-%d %H:%M"
    base = local.strftime(mask)
    if not with_label:
        return base
    off = local.strftime("%z")  # '+0700' / '-0500' / '' (UTC)
    if off and len(off) == 5:
        label = f"UTC{off[:3]}:{off[3:]}"
    elif off:
        label = f"UTC{off}"
    else:
        label = "UTC"
    return f"{base} ({label})"


def hex_pairs(value) -> str:
    """int / bytes / hex-string → 'AA:BB:CC' (uppercase, từng cặp byte)."""
    if isinstance(value, int):
        h = f"{value:X}"
    elif isinstance(value, (bytes, bytearray)):
        h = bytes(value).hex().upper()
    else:
        h = str(value).replace(":", "").replace(" ", "").upper()
    if len(h) % 2:
        h = "0" + h
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


_DN_LABELS = {
    "commonName":             "CN",
    "organizationName":       "O",
    "organizationalUnitName": "OU",
    "countryName":            "C",
    "stateOrProvinceName":    "ST",
    "localityName":           "L",
    "emailAddress":           "Email",
    "serialNumber":           "SerialNumber",
}


def dn_components(name: "x509.Name") -> "list[tuple[str, str]]":
    """x509.Name → list (nhãn, giá trị) đã tách từng thành phần DN."""
    out: "list[tuple[str, str]]" = []
    for attr in name:
        label = _DN_LABELS.get(attr.oid._name, attr.oid._name)
        out.append((label, str(attr.value)))
    return out


def describe_extension(ext) -> "list[str]":
    """
    Giải mã 1 extension X.509v3 thành các dòng dễ đọc theo từng loại, thay vì
    in repr thô. Fallback str(ext.value) cho extension không biết.
    """
    v = ext.value
    lines: "list[str]" = []
    try:
        if isinstance(v, x509.BasicConstraints):
            lines.append(f"CA: {v.ca}"
                         + (f", path_len: {v.path_length}"
                            if v.path_length is not None else ""))
        elif isinstance(v, x509.KeyUsage):
            flags = []
            for attr in ("digital_signature", "content_commitment",
                         "key_encipherment", "data_encipherment",
                         "key_agreement", "key_cert_sign", "crl_sign"):
                if getattr(v, attr, False):
                    flags.append(attr)
            # encipher_only/decipher_only chỉ hợp lệ khi key_agreement=True
            if v.key_agreement:
                for attr in ("encipher_only", "decipher_only"):
                    try:
                        if getattr(v, attr):
                            flags.append(attr)
                    except ValueError:
                        pass
            lines.append(", ".join(flags) or "(none)")
        elif isinstance(v, x509.ExtendedKeyUsage):
            lines.append(", ".join(oid._name for oid in v))
        elif isinstance(v, x509.SubjectAlternativeName):
            for dns in v.get_values_for_type(x509.DNSName):
                lines.append(f"DNS: {dns}")
            for ip in v.get_values_for_type(x509.IPAddress):
                lines.append(f"IP: {ip}")
        elif isinstance(v, x509.SubjectKeyIdentifier):
            lines.append(hex_pairs(v.digest))
        elif isinstance(v, x509.AuthorityKeyIdentifier):
            if v.key_identifier:
                lines.append(f"keyid: {hex_pairs(v.key_identifier)}")
            else:
                lines.append("(no key identifier)")
        elif isinstance(v, x509.CRLDistributionPoints):
            for dp in v:
                for gn in (dp.full_name or []):
                    lines.append(f"URI: {gn.value}")
        elif isinstance(v, x509.AuthorityInformationAccess):
            for ad in v:
                loc = getattr(ad.access_location, "value", ad.access_location)
                lines.append(f"{ad.access_method._name}: {loc}")
        else:
            lines.append(str(v))
    except Exception as e:  # noqa: BLE001 — không bao giờ để 1 ext làm vỡ dialog
        lines.append(f"(không decode được: {e})")
    return lines


def describe_public_key(pk) -> str:
    """Mô tả ngắn loại khóa + tham số (RSA bits / EC curve / Ed25519)."""
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
    if isinstance(pk, rsa.RSAPublicKey):
        return f"RSA {pk.key_size} bits"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"ECDSA ({pk.curve.name})"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return pk.__class__.__name__


def public_key_pem(pk) -> str:
    """PEM (SubjectPublicKeyInfo) của một public key object."""
    from cryptography.hazmat.primitives import serialization
    return pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii").strip()


class ChangePasswordDialog(tk.Toplevel):
    """Modal dialog — đổi mật khẩu user hiện tại."""

    def __init__(self, parent: tk.Misc, app):
        super().__init__(parent)
        self.app = app
        self.title("Đổi mật khẩu")
        self.geometry("360x220")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Mật khẩu cũ:").grid(
            row=0, column=0, sticky="e", pady=6, padx=4)
        self.old_pw = ttk.Entry(frame, show="•", width=24)
        self.old_pw.grid(row=0, column=1, pady=6, padx=4, sticky="ew")

        ttk.Label(frame, text="Mật khẩu mới:").grid(
            row=1, column=0, sticky="e", pady=6, padx=4)
        self.new_pw = ttk.Entry(frame, show="•", width=24)
        self.new_pw.grid(row=1, column=1, pady=6, padx=4, sticky="ew")

        ttk.Label(frame, text="Xác nhận:").grid(
            row=2, column=0, sticky="e", pady=6, padx=4)
        self.confirm_pw = ttk.Entry(frame, show="•", width=24)
        self.confirm_pw.grid(row=2, column=1, pady=6, padx=4, sticky="ew")

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=3, column=0, columnspan=2,
                     pady=(SPACE["md"], 0), sticky="ew")
        ttk.Button(btn_row, text="Đổi", style="Primary.TButton",
                   command=self.on_submit).pack(side=tk.RIGHT, padx=SPACE["xs"])
        ttk.Button(btn_row, text="Hủy", command=self.destroy).pack(
            side=tk.RIGHT, padx=SPACE["xs"])

        frame.columnconfigure(1, weight=1)
        self.old_pw.focus_set()
        for w in (self.old_pw, self.new_pw, self.confirm_pw):
            w.bind("<Return>", lambda e: self.on_submit())
        fit_to_content(self)

    def on_submit(self) -> None:
        old = self.old_pw.get()
        new = self.new_pw.get()
        confirm = self.confirm_pw.get()
        if new != confirm:
            messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp.")
            return
        try:
            change_password(
                self.app.session["id"], old, new, self.app.db_path,
            )
        except AuthError as e:
            messagebox.showerror("Đổi mật khẩu thất bại", str(e))
            return
        write_audit(
            self.app.db_path, self.app.session["id"], Action.PASSWORD_CHANGED,
            target_type="user", target_id=str(self.app.session["id"]),
        )
        messagebox.showinfo("Thành công", "Đã đổi mật khẩu.")
        self.destroy()


def build_dashboard_header(parent: ttk.Frame, app, role_label: str) -> ttk.Frame:
    """
    Header bar phía trên dashboard:
      [Role badge] [Username]                  [Đổi mật khẩu] [Đăng xuất]
    """
    bar = ttk.Frame(parent, padding=(SPACE["lg"], SPACE["md"]),
                    style="Surface.TFrame")
    bar.pack(fill=tk.X)

    # Role badge — chữ to + màu navy
    role_label_widget = ttk.Label(
        bar,
        text=f"  {role_label.upper()}  ",
        style="Surface.TLabel",
        foreground=COLOR["text_inverse"],
        background=COLOR["primary"],
        font=font("label"),
        padding=(SPACE["sm"], SPACE["xxs"]),
    )
    role_label_widget.pack(side=tk.LEFT)

    name_label = ttk.Label(
        bar,
        text=f"  {app.session['username']}",
        style="Surface.TLabel",
        font=font("heading_md"),
    )
    name_label.pack(side=tk.LEFT)

    ttk.Button(
        bar, text="Đăng xuất", style="Danger.TButton",
        command=app.logout, width=14,
    ).pack(side=tk.RIGHT, padx=(SPACE["xs"], 0))
    ttk.Button(
        bar, text="Đổi mật khẩu",
        command=lambda: ChangePasswordDialog(parent, app), width=14,
    ).pack(side=tk.RIGHT, padx=(SPACE["xs"], 0))

    # Separator dưới header
    ttk.Separator(parent, orient=tk.HORIZONTAL).pack(fill=tk.X)
    return bar


def coming_soon_frame(parent: tk.Misc, feature: str, milestone: str) -> ttk.Frame:
    """Placeholder frame cho features chưa làm xong."""
    frame = ttk.Frame(parent, padding=SPACE["xl"])
    ttk.Label(frame, text=feature, style="H1.TLabel").pack(pady=(0, SPACE["sm"]))
    ttk.Label(
        frame,
        text=f"Tính năng này sẽ được triển khai trong {milestone}.",
        style="Muted.TLabel",
    ).pack()
    return frame


# ── Hero section ─────────────────────────────────────────────────────────────

def hero_section(
    parent: tk.Misc,
    title: str,
    eyebrow: "str | None" = None,
    subtitle: str = "",
    description: str = "",
    primary_cta: "tuple[str, object] | None" = None,
    secondary_cta: "tuple[str, object] | None" = None,
    features: "list[tuple[str, str, str]] | None" = None,
    cols: int = 3,
) -> ttk.Frame:
    """
    SaaS-style hero: large headline + subtitle + CTAs, optional feature card grid.

    Bố cục:
      ┌──────────────────────────────────────────────────────┐
      │ ▔▔▔▔▔▔ (accent strip)                                │
      │                                                       │
      │ EYEBROW                                               │
      │ Hero title (DFVN Float, 36pt)                         │
      │ Subtitle (Montserrat 11pt, muted)                     │
      │ Description (Montserrat 10pt)                         │
      │                                                       │
      │ [Primary CTA]  [Secondary CTA]                        │
      └──────────────────────────────────────────────────────┘
      ┌──────────┐ ┌──────────┐ ┌──────────┐
      │ ◆ Title  │ │ ▣ Title  │ │ ◉ Title  │   ← feature cards
      │   desc   │ │   desc   │ │   desc   │
      └──────────┘ └──────────┘ └──────────┘

    Args:
      features: list of (glyph, title, desc) — glyph là unicode 1 ký tự dùng
                làm icon monochrome.
      cols: số cột feature cards (default 3).
    """
    container = ttk.Frame(parent)

    # ── Hero card ──
    hero = ttk.Frame(container, style="Hero.TFrame")
    hero.pack(fill=tk.X, padx=SPACE["xl"], pady=(SPACE["xl"], SPACE["lg"]))

    # Accent strip on top
    ttk.Frame(hero, style="HeroAccent.TFrame", height=4).pack(fill=tk.X)

    inner = ttk.Frame(hero, style="Hero.TFrame",
                      padding=(SPACE["xxxl"], SPACE["xxl"]))
    inner.pack(fill=tk.X)

    if eyebrow:
        ttk.Label(inner, text=eyebrow.upper(),
                  style="HeroEyebrow.TLabel").pack(anchor="w",
                                                   pady=(0, SPACE["xs"]))

    ttk.Label(inner, text=title, style="Hero.TLabel").pack(anchor="w")

    if subtitle:
        ttk.Label(
            inner, text=subtitle, style="HeroSubtitle.TLabel",
            wraplength=900, justify=tk.LEFT,
        ).pack(anchor="w", pady=(SPACE["sm"], 0))

    if description:
        ttk.Label(
            inner, text=description, style="HeroDesc.TLabel",
            wraplength=900, justify=tk.LEFT,
        ).pack(anchor="w", pady=(SPACE["md"], 0))

    if primary_cta or secondary_cta:
        cta_row = ttk.Frame(inner, style="Hero.TFrame")
        cta_row.pack(anchor="w", pady=(SPACE["xl"], 0))
        if primary_cta:
            label, cmd = primary_cta
            ttk.Button(cta_row, text=label,
                       style="Primary.TButton", command=cmd).pack(side=tk.LEFT)
        if secondary_cta:
            label, cmd = secondary_cta
            ttk.Button(cta_row, text=label, command=cmd).pack(
                side=tk.LEFT, padx=(SPACE["sm"], 0))

    # ── Feature cards grid ──
    if features:
        grid_wrap = ttk.Frame(container)
        grid_wrap.pack(fill=tk.X, padx=SPACE["xl"], pady=(0, SPACE["xl"]))
        ncols = min(cols, len(features))
        for i, (glyph, ftitle, fdesc) in enumerate(features):
            r, c = divmod(i, ncols)
            card = ttk.Frame(grid_wrap, style="Card.TFrame",
                             padding=(SPACE["lg"], SPACE["lg"]))
            card.grid(row=r, column=c, sticky="nsew",
                      padx=SPACE["xs"], pady=SPACE["xs"])
            ttk.Label(card, text=glyph, style="CardIcon.TLabel").pack(anchor="w")
            ttk.Label(card, text=ftitle, style="CardTitle.TLabel").pack(
                anchor="w", pady=(SPACE["sm"], 0))
            ttk.Label(
                card, text=fdesc, style="CardDesc.TLabel",
                wraplength=280, justify=tk.LEFT,
            ).pack(anchor="w", pady=(SPACE["xs"], 0))
        for c in range(ncols):
            grid_wrap.columnconfigure(c, weight=1, uniform="hero_card_col")

    return container


# ── Cert detail dialog (shared admin + customer) ─────────────────────────────

class CertDetailDialog(tk.Toplevel):
    """
    Modal hiển thị chi tiết cert. Dùng chung admin (A.8) và customer (B.6).

    Tabs:
      • Decoded — subject, issuer, serial, validity, extensions
      • PEM     — raw PEM + nút Copy + nút Save As
    """

    def __init__(self, parent: tk.Misc, cert_record: dict):
        super().__init__(parent)
        self.rec = cert_record
        self.title(f"Cert #{cert_record['id']} — {cert_record['common_name']}")
        self.geometry("820x600")
        self.transient(parent)

        self._build_header()
        self._build_tabs()
        self._build_buttons()
        fit_to_content(self)

    # ── Header (info row) ─────────────────────────────────────────────────────

    def _build_header(self) -> None:
        rec = self.rec
        lines = [
            f"ID:        #{rec['id']}  •  serial: {hex_pairs(rec['serial_hex'])}",
            f"Domain:    {rec['common_name']}",
            f"Owner:     {rec.get('owner_username') or rec.get('owner_id') or '—'}",
            f"Status:    {rec.get('status', '—').upper()}",
            f"Valid:     {fmt_local(rec.get('not_valid_before'))}  →  {fmt_local(rec.get('not_valid_after'))}",
            f"Issued at: {fmt_local(rec.get('issued_at'))}",
        ]
        if rec.get("renewed_from_id"):
            lines.append(f"Renewed from cert #{rec['renewed_from_id']}")
        if rec.get("revoked_at"):
            lines.append(
                f"REVOKED at {fmt_local(rec['revoked_at'])} — "
                f"{rec.get('revocation_reason') or '(no reason)'}"
            )

        info = "\n".join(lines)
        lbl = ttk.Label(
            self, text=info, justify=tk.LEFT,
            font=font("mono"), padding=(12, 10),
        )
        lbl.pack(anchor="w")

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def _build_tabs(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 6))

        nb.add(self._build_decoded_tab(nb), text="Decoded")
        nb.add(self._build_pem_tab(nb),     text="PEM")

    def _build_decoded_tab(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent)
        text = tk.Text(frame, font=font("body"), wrap=tk.WORD,
                       padx=10, pady=8)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        hfam, hsize, _ = font("heading_sm")
        text.tag_configure("h2", font=(hfam, hsize, "bold"),
                           foreground=COLOR["primary"], spacing1=10, spacing3=4)
        lfam, lsize, _ = font("label")
        text.tag_configure("key", font=(lfam, lsize, "bold"))

        def section(title: str) -> None:
            text.insert(tk.END, f"{title}\n", "h2")

        def kv(label: str, value: str) -> None:
            text.insert(tk.END, f"  {label}: ", "key")
            text.insert(tk.END, f"{value}\n")

        try:
            from cryptography.hazmat.primitives import hashes
            cert = x509.load_pem_x509_certificate(bytes(self.rec["cert_pem"]))
            pk = cert.public_key()

            section("Tổng quan")
            kv("Version", cert.version.name)
            kv("Serial", hex_pairs(cert.serial_number))
            kv("Signature Algorithm", cert.signature_algorithm_oid._name)
            kv("Public Key", describe_public_key(pk))

            section("Fingerprints")
            kv("SHA-256", hex_pairs(cert.fingerprint(hashes.SHA256())))
            kv("SHA-1", hex_pairs(cert.fingerprint(hashes.SHA1())))

            section("Subject")
            for lbl, val in dn_components(cert.subject):
                kv(lbl, val)

            section("Issuer")
            for lbl, val in dn_components(cert.issuer):
                kv(lbl, val)

            try:
                nb_t = cert.not_valid_before_utc
                na_t = cert.not_valid_after_utc
            except AttributeError:
                nb_t = cert.not_valid_before
                na_t = cert.not_valid_after
            section("Hiệu lực (Validity)")
            kv("Not Before", fmt_local(nb_t))
            kv("Not After", fmt_local(na_t))

            section("Extensions")
            exts = list(cert.extensions)
            if not exts:
                text.insert(tk.END, "  (không có extension)\n")
            for ext in exts:
                crit = " [critical]" if ext.critical else ""
                text.insert(tk.END, f"  • {ext.oid._name}{crit}\n", "key")
                for line in describe_extension(ext):
                    text.insert(tk.END, f"      {line}\n")

            section("Public Key (PEM)")
            text.insert(tk.END, public_key_pem(pk) + "\n")

            section("Signature value")
            text.insert(tk.END, hex_pairs(cert.signature) + "\n")
        except Exception as e:
            text.insert("1.0", f"Không decode được cert PEM: {e}")
        text.config(state=tk.DISABLED)
        return frame

    def _build_pem_tab(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent)
        text = tk.Text(frame, font=font("mono"), wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._pem_str = bytes(self.rec["cert_pem"]).decode("ascii", errors="replace")
        text.insert("1.0", self._pem_str)
        text.config(state=tk.DISABLED)
        return frame

    # ── Buttons ───────────────────────────────────────────────────────────────

    def _build_buttons(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(bar, text="Copy PEM", command=self._on_copy).pack(side=tk.LEFT)
        ttk.Button(bar, text="Save PEM as…", command=self._on_save).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(bar, text="Đóng", command=self.destroy).pack(side=tk.RIGHT)

    def _on_copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._pem_str)

    def _on_save(self) -> None:
        from tkinter import filedialog
        default_name = (
            f"{self.rec['common_name']}-{self.rec['serial_hex'][:8]}.crt"
        )
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Lưu cert PEM",
            defaultextension=".crt",
            initialfile=default_name,
            filetypes=(("PEM cert", "*.crt *.pem"), ("All files", "*.*")),
        )
        if not path:
            return
        with open(path, "wb") as f:
            f.write(bytes(self.rec["cert_pem"]))
        messagebox.showinfo("Đã lưu", f"Đã lưu cert vào:\n{path}")
