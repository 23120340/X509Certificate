"""
ui/theme.py
-----------
Design tokens + ttk style applier cho toàn ứng dụng.

Triết lý:
  • Light mode, navy + slate palette (đáng tin, dành cho phiên dài).
  • Typography rút gọn còn 2 font: DFVN Float cho mọi title/heading
    (display, h1, h2, h3, h4), Montserrat cho mọi body/label/caption/mono.
  • 4/8 spacing rhythm.
  • Status colors có cả tone đậm (text) lẫn tone nhạt (background).
  • Hover/pressed/disabled states cho button qua `Style.map`.

Tkinter giới hạn:
  • Không có glassmorphism / backdrop-blur thật. Chúng ta thay thế bằng
    layered surfaces (background → surface → surface_alt) + border tinh tế.
  • Không có rounded corners trên Frame/Label. Có thể có chút trên ttk Button
    tuỳ theme. Dùng `clam` theme làm baseline vì hỗ trợ custom colors tốt.

Usage:
  from ui.theme import apply_theme, COLOR, FONT, SPACE, font
  apply_theme(root)
  ttk.Label(parent, text="Hi", font=font("heading_xl"), foreground=COLOR["text"])
"""

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk


# ── Color tokens ─────────────────────────────────────────────────────────────

COLOR = {
    # Brand
    "primary":          "#1E3A8A",   # navy-900 — primary actions, links
    "primary_hover":    "#1E40AF",   # navy-800
    "primary_active":   "#172554",   # navy-950 (pressed)
    "accent":           "#10B981",   # emerald-500 — success/security signals
    "accent_hover":     "#059669",

    # Surface — layered
    "bg":               "#F8FAFC",   # slate-50 — app window background
    "surface":          "#FFFFFF",   # cards, panels
    "surface_alt":      "#F1F5F9",   # slate-100 — alt rows, hover bg
    "surface_subtle":   "#F8FAFC",   # slate-50 — sidebar

    # Border
    "border":           "#E2E8F0",   # slate-200 — default
    "border_strong":    "#CBD5E1",   # slate-300 — input focus
    "border_subtle":    "#F1F5F9",   # slate-100 — alternating row separators

    # Text
    "text":             "#0F172A",   # slate-900 — body
    "text_muted":       "#475569",   # slate-600 — secondary
    "text_subtle":      "#94A3B8",   # slate-400 — captions, placeholders
    "text_inverse":     "#FFFFFF",
    "text_link":        "#1E40AF",   # navy-800

    # Status — text/icon tone
    "success":          "#059669",
    "warning":          "#D97706",
    "danger":           "#DC2626",
    "info":             "#2563EB",

    # Status — soft background (for badges)
    "success_bg":       "#ECFDF5",
    "warning_bg":       "#FFFBEB",
    "danger_bg":        "#FEF2F2",
    "info_bg":          "#EFF6FF",

    # Misc
    "shadow":           "#0F172A",   # not actually used (Tk no shadow); for reference
    "focus_ring":       "#3B82F6",   # blue-500
}


# ── Spacing scale (4/8 rhythm) ───────────────────────────────────────────────

SPACE = {
    "xxs": 2,
    "xs":  4,
    "sm":  8,
    "md":  12,
    "lg":  16,
    "xl":  24,
    "xxl": 32,
    "xxxl": 48,
}


# ── Font resolution ──────────────────────────────────────────────────────────

# Chỉ 2 font: DFVN Float cho title, Montserrat cho mọi nội dung khác.
# Các tên phía sau chỉ là fallback an toàn nếu font chính không có sẵn trên
# máy khác — primary luôn là 2 font đã chọn.
HEADING_FONT_CHAIN = [
    "Montserrat",     # fallback nếu DFVN Float không có
]

BODY_FONT_CHAIN = [
    "Montserrat",     # body chính
]

# Mono dùng chung BODY chain — chấp nhận mất alignment của PEM/serial để giữ
# nguyên tắc 2 font.
MONO_FONT_CHAIN = BODY_FONT_CHAIN


_FONT_CACHE: "dict[str, str]" = {}


def _available_fonts(root: "tk.Misc | None" = None) -> "set[str]":
    """Lấy set fonts đang cài trên hệ thống. Cache lần đầu."""
    if "_families" in _FONT_CACHE:
        return _FONT_CACHE["_families"]   # type: ignore
    families = set(tkfont.families(root))
    _FONT_CACHE["_families"] = families   # type: ignore
    return families


def resolve_family(chain: "list[str]", root: "tk.Misc | None" = None) -> str:
    """Tìm font đầu tiên trong chain có cài trên hệ thống. Fallback cuối chain."""
    available = _available_fonts(root)
    for name in chain:
        if name in available:
            return name
    return chain[-1]  # nếu chẳng còn gì thì dùng default cuối (Arial/monospace)


# Font role spec: (chain, size, weight). Resolve lazy.
FONT_SPEC = {
    # Heading — all DFVN Float
    "hero":         (HEADING_FONT_CHAIN, 36, "bold"),
    "display":      (HEADING_FONT_CHAIN, 24, "bold"),
    "heading_xl":   (HEADING_FONT_CHAIN, 18, "bold"),
    "heading_lg":   (HEADING_FONT_CHAIN, 15, "bold"),
    "heading_md":   (HEADING_FONT_CHAIN, 12, "bold"),
    "heading_sm":   (HEADING_FONT_CHAIN, 10, "bold"),

    # Body
    "body_lg":      (BODY_FONT_CHAIN,    11, "normal"),
    "body":         (BODY_FONT_CHAIN,    10, "normal"),
    "body_sm":      (BODY_FONT_CHAIN,    9,  "normal"),
    "caption":      (BODY_FONT_CHAIN,    8,  "normal"),
    "label":        (BODY_FONT_CHAIN,    9,  "bold"),

    # Mono
    "mono":         (MONO_FONT_CHAIN,    9,  "normal"),
    "mono_sm":      (MONO_FONT_CHAIN,    8,  "normal"),
}


def font(role: str, root: "tk.Misc | None" = None) -> tuple:
    """
    Resolve 1 font role → tuple (family, size, weight) cho Tkinter.

    Lần đầu gọi cho mỗi role sẽ cache family đã resolve.
    """
    cache_key = f"role:{role}"
    if cache_key in _FONT_CACHE:
        return _FONT_CACHE[cache_key]    # type: ignore
    if role not in FONT_SPEC:
        raise KeyError(f"Unknown font role: {role!r}")
    chain, size, weight = FONT_SPEC[role]
    family = resolve_family(chain, root)
    resolved = (family, size, weight)
    _FONT_CACHE[cache_key] = resolved    # type: ignore
    return resolved


# ── Status helpers ───────────────────────────────────────────────────────────

STATUS_FG = {
    "active":   COLOR["success"],
    "pending":  COLOR["warning"],
    "approved": COLOR["success"],
    "rejected": COLOR["danger"],
    "revoked":  COLOR["danger"],
    "expired":  COLOR["text_subtle"],
    "valid":    COLOR["success"],
}

STATUS_BG = {
    "active":   COLOR["success_bg"],
    "pending":  COLOR["warning_bg"],
    "approved": COLOR["success_bg"],
    "rejected": COLOR["danger_bg"],
    "revoked":  COLOR["danger_bg"],
    "expired":  COLOR["surface_alt"],
    "valid":    COLOR["success_bg"],
}


# ── Apply theme to ttk ───────────────────────────────────────────────────────

def apply_theme(root: tk.Tk) -> None:
    """
    Cấu hình ttk Style cho toàn app. Gọi sau khi tạo Tk root.

    Sử dụng theme `clam` làm base vì support custom colors tốt nhất trên
    cả Windows/Linux/macOS. Override các widget chính:
      • TFrame, TLabel, TLabelframe(.Label)
      • TButton (default, Primary, Accent, Danger, Ghost variants)
      • TEntry, TCombobox, TNotebook(.Tab)
      • Treeview + Treeview.Heading + alternating row tag
      • TScrollbar, TSeparator, TProgressbar
    """
    root.configure(bg=COLOR["bg"])
    root.option_add("*Font", font("body", root))

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    # ── Frame & layout ──
    style.configure("TFrame", background=COLOR["bg"])
    style.configure("Surface.TFrame", background=COLOR["surface"])
    style.configure("Sidebar.TFrame", background=COLOR["surface_subtle"])
    style.configure("Card.TFrame",
                    background=COLOR["surface"],
                    relief="solid",
                    bordercolor=COLOR["border"],
                    borderwidth=1)
    # Hero card — same surface bg, slightly stronger border, used by hero_section()
    style.configure("Hero.TFrame",
                    background=COLOR["surface"],
                    relief="solid",
                    bordercolor=COLOR["border"],
                    borderwidth=1)
    # Accent strip on top of hero (navy bar) — purely decorative
    style.configure("HeroAccent.TFrame",
                    background=COLOR["primary"])

    style.configure(
        "TLabelframe",
        background=COLOR["surface"],
        bordercolor=COLOR["border"],
        relief="solid", borderwidth=1,
    )
    style.configure(
        "TLabelframe.Label",
        background=COLOR["surface"],
        foreground=COLOR["text"],
        font=font("heading_sm", root),
    )

    # ── Label ──
    style.configure(
        "TLabel",
        background=COLOR["bg"],
        foreground=COLOR["text"],
        font=font("body", root),
    )
    style.configure("Surface.TLabel", background=COLOR["surface"])
    style.configure("Sidebar.TLabel", background=COLOR["surface_subtle"])
    style.configure(
        "Display.TLabel",
        font=font("display", root),
        foreground=COLOR["text"],
    )
    style.configure(
        "H1.TLabel",
        font=font("heading_xl", root),
        foreground=COLOR["text"],
    )
    style.configure(
        "H2.TLabel",
        font=font("heading_lg", root),
        foreground=COLOR["text"],
    )
    style.configure(
        "Muted.TLabel",
        foreground=COLOR["text_muted"],
        font=font("body_sm", root),
    )
    style.configure(
        "Subtle.TLabel",
        foreground=COLOR["text_subtle"],
        font=font("caption", root),
    )
    style.configure(
        "Mono.TLabel",
        font=font("mono", root),
        foreground=COLOR["text"],
    )

    # ── Hero label variants (all on surface bg) ──
    style.configure(
        "Hero.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["text"],
        font=font("hero", root),
    )
    style.configure(
        "HeroEyebrow.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["primary"],
        font=font("label", root),
    )
    style.configure(
        "HeroSubtitle.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["text_muted"],
        font=font("body_lg", root),
    )
    style.configure(
        "HeroDesc.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["text"],
        font=font("body", root),
    )

    # ── Feature card label variants ──
    style.configure(
        "CardIcon.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["primary"],
        font=(font("body", root)[0], 22, "bold"),
    )
    style.configure(
        "CardTitle.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["text"],
        font=font("heading_md", root),
    )
    style.configure(
        "CardDesc.TLabel",
        background=COLOR["surface"],
        foreground=COLOR["text_muted"],
        font=font("body_sm", root),
    )

    # ── Button — base ──
    style.configure(
        "TButton",
        font=font("body", root),
        padding=(SPACE["md"], SPACE["sm"]),
        background=COLOR["surface"],
        foreground=COLOR["text"],
        bordercolor=COLOR["border_strong"],
        focusthickness=1,
        focuscolor=COLOR["focus_ring"],
        relief="flat",
        borderwidth=1,
    )
    style.map(
        "TButton",
        background=[
            ("active",  COLOR["surface_alt"]),
            ("pressed", COLOR["border"]),
            ("disabled", COLOR["surface_alt"]),
        ],
        foreground=[("disabled", COLOR["text_subtle"])],
        bordercolor=[("active", COLOR["border_strong"])],
    )

    # ── Button — Primary (navy filled) ──
    style.configure(
        "Primary.TButton",
        background=COLOR["primary"],
        foreground=COLOR["text_inverse"],
        bordercolor=COLOR["primary"],
        font=font("label", root),
        padding=(SPACE["lg"], SPACE["sm"]),
    )
    style.map(
        "Primary.TButton",
        background=[
            ("active",  COLOR["primary_hover"]),
            ("pressed", COLOR["primary_active"]),
            ("disabled", COLOR["text_subtle"]),
        ],
        foreground=[("disabled", COLOR["surface"])],
    )

    # ── Button — Accent (emerald filled) — for "Publish CRL", confirm actions
    style.configure(
        "Accent.TButton",
        background=COLOR["accent"],
        foreground=COLOR["text_inverse"],
        bordercolor=COLOR["accent"],
        font=font("label", root),
        padding=(SPACE["lg"], SPACE["sm"]),
    )
    style.map(
        "Accent.TButton",
        background=[
            ("active",  COLOR["accent_hover"]),
            ("pressed", COLOR["accent_hover"]),
            ("disabled", COLOR["text_subtle"]),
        ],
    )

    # ── Button — Danger ──
    style.configure(
        "Danger.TButton",
        background=COLOR["danger"],
        foreground=COLOR["text_inverse"],
        bordercolor=COLOR["danger"],
        font=font("label", root),
        padding=(SPACE["lg"], SPACE["sm"]),
    )
    style.map(
        "Danger.TButton",
        background=[
            ("active",  "#B91C1C"),
            ("pressed", "#991B1B"),
            ("disabled", COLOR["text_subtle"]),
        ],
    )

    # ── Button — Ghost (nav sidebar) ──
    style.configure(
        "Ghost.TButton",
        background=COLOR["surface_subtle"],
        foreground=COLOR["text"],
        bordercolor=COLOR["surface_subtle"],
        font=font("body", root),
        padding=(SPACE["md"], SPACE["sm"]),
        anchor="w",
    )
    style.map(
        "Ghost.TButton",
        background=[
            ("active",  COLOR["surface_alt"]),
            ("pressed", COLOR["border"]),
        ],
    )

    # ── Entry ──
    style.configure(
        "TEntry",
        fieldbackground=COLOR["surface"],
        foreground=COLOR["text"],
        bordercolor=COLOR["border_strong"],
        lightcolor=COLOR["border_strong"],
        darkcolor=COLOR["border_strong"],
        insertcolor=COLOR["text"],
        padding=(SPACE["sm"], SPACE["xs"]),
    )
    style.map(
        "TEntry",
        bordercolor=[("focus", COLOR["focus_ring"])],
        lightcolor=[("focus", COLOR["focus_ring"])],
        darkcolor=[("focus", COLOR["focus_ring"])],
    )

    # ── Combobox ──
    style.configure(
        "TCombobox",
        fieldbackground=COLOR["surface"],
        background=COLOR["surface"],
        foreground=COLOR["text"],
        bordercolor=COLOR["border_strong"],
        lightcolor=COLOR["border_strong"],
        darkcolor=COLOR["border_strong"],
        arrowcolor=COLOR["text_muted"],
        padding=(SPACE["sm"], SPACE["xs"]),
    )
    style.map(
        "TCombobox",
        bordercolor=[("focus", COLOR["focus_ring"])],
        fieldbackground=[("readonly", COLOR["surface"])],
    )

    # ── Notebook ──
    style.configure(
        "TNotebook",
        background=COLOR["bg"],
        bordercolor=COLOR["border"],
        tabmargins=(0, 0, 0, 0),
    )
    style.configure(
        "TNotebook.Tab",
        background=COLOR["surface_alt"],
        foreground=COLOR["text_muted"],
        padding=(SPACE["lg"], SPACE["sm"]),
        font=font("label", root),
        bordercolor=COLOR["border"],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLOR["surface"])],
        foreground=[("selected", COLOR["primary"])],
        expand=[("selected", (0, 0, 0, 0))],
    )

    # ── Treeview ──
    style.configure(
        "Treeview",
        background=COLOR["surface"],
        fieldbackground=COLOR["surface"],
        foreground=COLOR["text"],
        bordercolor=COLOR["border"],
        rowheight=26,
        font=font("body_sm", root),
    )
    style.configure(
        "Treeview.Heading",
        background=COLOR["surface_alt"],
        foreground=COLOR["text_muted"],
        font=font("label", root),
        padding=(SPACE["sm"], SPACE["sm"]),
        relief="flat",
        bordercolor=COLOR["border"],
    )
    style.map(
        "Treeview",
        background=[("selected", COLOR["info_bg"])],
        foreground=[("selected", COLOR["primary"])],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", COLOR["border_subtle"])],
    )

    # ── Scrollbar ──
    style.configure(
        "TScrollbar",
        background=COLOR["surface_alt"],
        troughcolor=COLOR["bg"],
        bordercolor=COLOR["border"],
        arrowcolor=COLOR["text_muted"],
    )
    style.map(
        "TScrollbar",
        background=[("active", COLOR["border"])],
    )

    # ── Separator ──
    style.configure("TSeparator", background=COLOR["border"])

    # ── Checkbutton / Radiobutton ──
    style.configure(
        "TCheckbutton",
        background=COLOR["surface"],
        foreground=COLOR["text"],
        font=font("body", root),
        focuscolor=COLOR["focus_ring"],
    )
    style.configure(
        "TRadiobutton",
        background=COLOR["surface"],
        foreground=COLOR["text"],
        font=font("body", root),
        focuscolor=COLOR["focus_ring"],
    )


# ── Helper: Treeview row tag configuration ────────────────────────────────────

def configure_tree_status_tags(tree: ttk.Treeview) -> None:
    """Áp dụng STATUS_FG cho tag tên giống status. Dùng:
        tree.insert(..., tags=(row["status"],))
    """
    for status, fg in STATUS_FG.items():
        tree.tag_configure(status, foreground=fg)
    # Alternating rows
    tree.tag_configure("oddrow", background=COLOR["surface_alt"])
