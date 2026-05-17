"""
ui/common.py
------------
Widget dùng chung cho cả admin và customer dashboard:
  • ChangePasswordDialog — modal dialog đổi mật khẩu (A.2 / B.3)
  • build_dashboard_header — header bar có user info + nút Đổi mật khẩu + Đăng xuất
  • coming_soon_frame — placeholder cho các tính năng chưa làm
"""

import tkinter as tk
from tkinter import ttk, messagebox

from services.auth import change_password, AuthError
from services.audit import write_audit, Action
from ui.theme import COLOR, SPACE, font


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

    # ── Header (info row) ─────────────────────────────────────────────────────

    def _build_header(self) -> None:
        rec = self.rec
        lines = [
            f"ID:        #{rec['id']}  •  serial: {rec['serial_hex']}",
            f"Domain:    {rec['common_name']}",
            f"Owner:     {rec.get('owner_username') or rec.get('owner_id') or '—'}",
            f"Status:    {rec.get('status', '—').upper()}",
            f"Valid:     {rec['not_valid_before']}  →  {rec['not_valid_after']}",
            f"Issued at: {rec['issued_at']}",
        ]
        if rec.get("renewed_from_id"):
            lines.append(f"Renewed from cert #{rec['renewed_from_id']}")
        if rec.get("revoked_at"):
            lines.append(
                f"REVOKED at {rec['revoked_at']} — "
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
        text = tk.Text(frame, font=font("mono"), wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(bytes(self.rec["cert_pem"]))
            lines = [
                f"Version          : {cert.version.name}",
                f"Serial           : {cert.serial_number:#x}",
                f"Signature Algo   : {cert.signature_algorithm_oid._name}",
                f"Issuer           : {cert.issuer.rfc4514_string()}",
                f"Subject          : {cert.subject.rfc4514_string()}",
            ]
            try:
                nb_t = cert.not_valid_before_utc
                na_t = cert.not_valid_after_utc
            except AttributeError:
                nb_t = cert.not_valid_before
                na_t = cert.not_valid_after
            lines.append(f"Not Before       : {nb_t}")
            lines.append(f"Not After        : {na_t}")
            pk = cert.public_key()
            if hasattr(pk, "key_size"):
                lines.append(
                    f"Public Key       : {pk.__class__.__name__} {pk.key_size} bits"
                )
            lines.append("")
            lines.append("=== Extensions ===")
            for ext in cert.extensions:
                lines.append(f"  • {ext.oid._name}  (critical={ext.critical})")
                lines.append(f"      {ext.value}")
            text.insert("1.0", "\n".join(lines))
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
