/*
 * docs/build_deck.js
 * ------------------
 * Build slide thuyết trình đồ án MHUD — X.509 Certificate Management.
 *
 * Cách chạy:
 *   $env:NODE_PATH=(npm root -g); node docs/build_deck.js
 * (NODE_PATH trỏ về global npm root vì pptxgenjs cài global, không có
 *  node_modules local.)
 *
 * Output:
 *   docs/MHUD_X509_presentation.pptx
 */

const pptxgen = require("pptxgenjs");

// ── Theme — based on "Purple Black and Pink Gradient Modern Bold..." ────────
// Template language: near-black canvas, hot-magenta/violet highlights,
// orange rim light, and reusable 3D abstract materials from the reference deck.
const C = {
  navy:    "7B2CFF",   // electric violet
  teal:    "F72585",   // hot pink
  midnight:"040109",
  cyan:    "00D1FF",   // cyber secondary accent
  bg:      "06030C",
  card:    "130A1D",
  card2:   "20102D",
  text:    "F8F7FF",
  muted:   "BDB4CF",
  border:  "7E2BCE",
  white:   "FFFFFF",
  ice:     "F4D7FF",
  success: "24C77E",
  warning: "FFB000",
  danger:  "FF477E",
  orange:  "FF7A1A",
  smoke:   "2A2235",
};

const A = {
  blurA:       "docs/assets/futuristic/primary_blur_a.jpeg",
  ring:        "docs/assets/futuristic/primary_ring.png",
  glassLoops:  "docs/assets/futuristic/glass_loops.png",
  glassOrb:    "docs/assets/futuristic/glass_orb.png",
  glassTorus:  "docs/assets/futuristic/glass_torus.png",
  fingerprint: "docs/assets/futuristic/fingerprint_scan.jpeg",
  lockIcon:    "docs/assets/futuristic/pink_lock_icon.png",
};

const FONT = "Montserrat";
const MONO = "Consolas";

// ── pptx setup ───────────────────────────────────────────────────────────────
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";  // 10" × 5.625"
pres.author = "Nhóm đồ án MHUD";
pres.title  = "Hệ thống Quản lý CA X.509";
pres.subject = "Đồ án môn Mã hoá & Ứng dụng";

const W = 10, H = 5.625;

// Helper: fresh shadow object (pptxgenjs mutates option objects in-place)
const shadow = () => ({
  type: "outer", color: "000000", blur: 12, offset: 2,
  angle: 90, opacity: 0.26,
});

// ── Layout helpers ───────────────────────────────────────────────────────────

function addFuturisticBackdrop(slide, pageNum, mode = "content") {
  const base = A.blurA;
  slide.background = { color: C.bg };
  slide.addImage({
    path: base,
    x: 0, y: 0, w: W, h: H,
    sizing: { type: "cover", w: W, h: H },
    transparency: mode === "hero" ? 12 : 24,
  });

  slide.addShape(pres.shapes.OVAL, {
    x: -0.45, y: -0.25, w: 1.25, h: 1.25,
    fill: { color: C.midnight, transparency: 100 },
    line: { color: C.teal, width: 1.2, transparency: 42 },
  });
  slide.addShape(pres.shapes.OVAL, {
    x: 8.78, y: 4.15, w: 0.70, h: 0.70,
    fill: { color: C.midnight, transparency: 100 },
    line: { color: C.orange, width: 0.75, transparency: 55 },
  });

  const decor = [];
  if (pageNum % 9 === 0) decor.push({ path: A.glassOrb,   x: 8.25, y: 0.65, w: 1.25, h: 1.25, t: 50 });
  if (pageNum % 8 === 0) decor.push({ path: A.glassTorus, x: 7.85, y: 3.75, w: 1.50, h: 1.05, t: 48 });
  if (pageNum % 10 === 0) decor.push({ path: A.glassLoops, x: 0.15, y: 3.55, w: 1.45, h: 1.00, t: 52 });
  if ([3, 15, 18, 21, 22, 23].includes(pageNum)) {
    decor.push({ path: A.lockIcon, x: 8.70, y: 0.75, w: 0.55, h: 0.55, t: 28 });
  }
  if ([7, 16, 22].includes(pageNum)) {
    decor.push({ path: A.fingerprint, x: 7.85, y: 3.62, w: 1.35, h: 0.92, t: 54 });
  }

  decor.forEach(d => {
    slide.addImage({ path: d.path, x: d.x, y: d.y, w: d.w, h: d.h, transparency: d.t });
  });

  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: W, h: H,
    fill: { color: C.midnight, transparency: mode === "hero" ? 18 : 10 },
    line: { type: "none" },
  });

  // Navigation chips mimic the reference template while doubling as context.
  const nav = ["HCMUS", "X.509", "PKI", "DEMO"];
  nav.forEach((n, i) => {
    slide.addText(n, {
      x: 6.34 + i * 0.72, y: 0.16, w: 0.58, h: 0.16,
      fontSize: 5.5, fontFace: FONT, bold: i === 1,
      color: i === 1 ? C.teal : C.ice,
      align: "center", margin: 0,
      charSpacing: 1,
    });
  });
}

function addAccent(slide) {
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.08, h: H,
    fill: { color: C.teal }, line: { type: "none" },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.08, y: 0, w: 0.035, h: H,
    fill: { color: C.orange }, line: { type: "none" },
  });
}

function addFooter(slide, pageNum, total) {
  slide.addShape(pres.shapes.LINE, {
    x: 0.5, y: 5.30, w: 9, h: 0,
    line: { color: C.border, width: 0.35, transparency: 24 },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.5, y: 5.36, w: 0.05, h: 0.18,
    fill: { color: C.teal }, line: { type: "none" },
  });
  slide.addText("HCMUS · FIT · MHUD", {
    x: 0.62, y: 5.32, w: 4, h: 0.25,
    fontSize: 9, fontFace: FONT, color: C.ice, bold: true,
    charSpacing: 3, margin: 0,
  });
  slide.addText("Tìm hiểu X.509 và thư viện lập trình", {
    x: 2.5, y: 5.32, w: 5, h: 0.25,
    fontSize: 9, fontFace: FONT, color: C.muted, italic: true,
    align: "right", margin: 0,
  });
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 8.85, y: 5.30, w: 0.65, h: 0.30, rectRadius: 0.08,
    fill: { color: C.teal }, line: { color: C.orange, width: 0.35 },
  });
  slide.addText(`${pageNum} / ${total}`, {
    x: 8.85, y: 5.30, w: 0.65, h: 0.30,
    fontSize: 9, fontFace: FONT, color: C.white, bold: true,
    align: "center", valign: "middle", margin: 0,
  });
}

function addTitle(slide, title, subtitle) {
  slide.addText(title, {
    x: 0.5, y: 0.42, w: 8.85, h: 0.52,
    fontSize: 24, fontFace: FONT, bold: true, color: C.white, margin: 0,
    breakLine: false,
  });
  if (subtitle) {
    slide.addText(subtitle, {
      x: 0.5, y: 0.98, w: 8.55, h: 0.30,
      fontSize: 10.5, fontFace: FONT, color: C.ice, italic: true, margin: 0,
    });
  }
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.5, y: 0.26, w: 0.40, h: 0.05,
    fill: { color: C.teal }, line: { type: "none" },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.92, y: 0.26, w: 0.22, h: 0.05,
    fill: { color: C.orange }, line: { type: "none" },
  });
}

function newContentSlide(title, subtitle, pageNum, total) {
  const slide = pres.addSlide();
  addFuturisticBackdrop(slide, pageNum, "content");
  addAccent(slide);
  addTitle(slide, title, subtitle);
  addFooter(slide, pageNum, total);
  return slide;
}

function newSectionSlide(label, big, pageNum, total) {
  const slide = pres.addSlide();
  addFuturisticBackdrop(slide, pageNum, "hero");
  slide.addText(label.toUpperCase(), {
    x: 0.6, y: 2.0, w: 9, h: 0.4,
    fontSize: 14, fontFace: FONT, color: C.teal, bold: true,
    charSpacing: 8, margin: 0,
  });
  slide.addText(big, {
    x: 0.6, y: 2.45, w: 9, h: 1.2,
    fontSize: 40, fontFace: FONT, bold: true, color: C.white, margin: 0,
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.6, y: 3.7, w: 1.2, h: 0.06,
    fill: { color: C.teal }, line: { type: "none" },
  });
  slide.addText(`${pageNum} / ${total}`, {
    x: 8.5, y: 5.32, w: 1, h: 0.25,
    fontSize: 9, fontFace: FONT, color: C.ice, align: "right", margin: 0,
  });
  return slide;
}

// Bullet list builder — rich text array with bullets
function bullets(items, opts = {}) {
  const arr = items.map((t, i) => {
    if (typeof t === "string") {
      return {
        text: t,
        options: { bullet: { code: "25A0" }, breakLine: i < items.length - 1 },
      };
    }
    // {text, sub} → main bullet + sub-line muted
    const out = [{
      text: t.text,
      options: { bullet: { code: "25A0" }, breakLine: !!t.sub || i < items.length - 1 },
    }];
    if (t.sub) {
      out.push({
        text: "   " + t.sub,
        options: {
          color: C.muted, fontSize: (opts.fontSize || 14) - 2,
          breakLine: i < items.length - 1,
        },
      });
    }
    return out;
  }).flat();
  return arr;
}

// Card with optional accent stripe on top
function card(slide, x, y, w, h, opts = {}) {
  const fill = { color: opts.fill || C.card };
  if (!opts.fill || opts.transparency !== undefined) {
    fill.transparency = opts.transparency ?? 4;
  }
  slide.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h,
    fill,
    line: { color: opts.border || C.border, width: 0.75, transparency: 18 },
    shadow: shadow(),
  });
  if (opts.accent) {
    slide.addShape(pres.shapes.RECTANGLE, {
      x, y, w, h: 0.06,
      fill: { color: opts.accent }, line: { type: "none" },
    });
  }
}

// Pill/badge
function pill(slide, x, y, w, h, text, color, bg) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h, rectRadius: 0.08,
    fill: { color: bg }, line: { type: "none" },
  });
  slide.addText(text, {
    x, y, w, h, fontSize: 10, fontFace: FONT, bold: true,
    color, align: "center", valign: "middle", margin: 0,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
const TOTAL = 27;

// ── 1. Title slide — main template reinterpretation ─────────────────────────
{
  const s = pres.addSlide();
  addFuturisticBackdrop(s, 1, "hero");
  s.addImage({
    path: A.ring,
    x: -0.95, y: -1.15, w: 4.1, h: 6.1,
    transparency: 4,
  });
  s.addImage({
    path: A.glassTorus,
    x: 7.45, y: 3.55, w: 1.75, h: 1.25,
    transparency: 18,
  });

  s.addImage({
    path: "docs/assets/fit_hcmus_30y.png",
    x: 8.25, y: 0.38, w: 1.15, h: 1.15,
  });

  s.addText("TRƯỜNG ĐẠI HỌC KHOA HỌC TỰ NHIÊN · KHOA CNTT", {
    x: 1.02, y: 0.42, w: 6.9, h: 0.22,
    fontSize: 8.2, fontFace: FONT, bold: true, color: C.ice,
    charSpacing: 2.8, margin: 0,
  });
  s.addText("ĐỒ ÁN MÔN MÃ HOÁ ỨNG DỤNG", {
    x: 1.42, y: 0.78, w: 4.4, h: 0.24,
    fontSize: 8.8, fontFace: FONT, color: C.teal, bold: true,
    charSpacing: 4.2, margin: 0,
  });

  s.addText("X.509", {
    x: 2.10, y: 1.52, w: 3.35, h: 0.82,
    fontSize: 48, fontFace: FONT, bold: true, color: C.white,
    margin: 0,
  });
  s.addText("Certificate", {
    x: 2.12, y: 2.24, w: 4.80, h: 0.58,
    fontSize: 33, fontFace: FONT, bold: true, color: C.teal,
    margin: 0,
  });
  s.addText("Management System", {
    x: 2.12, y: 2.75, w: 5.1, h: 0.45,
    fontSize: 24, fontFace: FONT, bold: true, color: "8D859A",
    margin: 0,
  });
  s.addText("Hệ thống quản lý và cấp phát chứng nhận X.509 cho dịch vụ website", {
    x: 2.16, y: 3.35, w: 5.9, h: 0.30,
    fontSize: 11, fontFace: FONT, color: C.ice,
    margin: 0,
  });

  const meta = [
    { label: "GVHD", value: "Lương Vĩ Minh · Trương Toàn Thịnh" },
    { label: "NHÓM", value: "Nhóm 7" },
    { label: "TPHCM", value: "06 / 04 / 2026" },
  ];
  meta.forEach((m, i) => {
    const x = 2.18 + i * 2.28;
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: 4.22, w: 1.96, h: 0.62,
      fill: { color: C.card2, transparency: 6 },
      line: { color: i === 0 ? C.teal : C.border, width: 0.65, transparency: 6 },
    });
    s.addText(m.label, {
      x: x + 0.16, y: 4.32, w: 1.64, h: 0.15,
      fontSize: 6.8, fontFace: FONT, bold: true, color: C.orange,
      charSpacing: 2, align: "center", margin: 0,
    });
    s.addText(m.value, {
      x: x + 0.12, y: 4.50, w: 1.72, h: 0.24,
      fontSize: i === 0 ? 7.3 : 8.8, fontFace: FONT, color: C.white,
      align: "center", margin: 0,
    });
  });
  addFooter(s, 1, TOTAL);
}

// ── 2. Bài toán ──────────────────────────────────────────────────────────────
{
  const s = newContentSlide("Bài toán", "Vì sao cần hệ thống PKI cho website?", 2, TOTAL);

  // Left: problem statement
  s.addText("Trình duyệt tin cậy website nhờ đâu?", {
    x: 0.5, y: 1.5, w: 5.3, h: 0.4,
    fontSize: 16, fontFace: FONT, bold: true, color: C.text, margin: 0,
  });

  s.addText(bullets([
    { text: "Mỗi website TLS có chứng nhận X.509", sub: "Bind public key ↔ domain, ký bởi CA" },
    { text: "CA = bên thứ ba mà cả browser + server đều tin",   sub: "Root CA cert phân phối sẵn trong trust store của OS" },
    { text: "Cert có vòng đời: phát hành → renew → revoke",    sub: "Khi private key bị lộ → revoke + cập nhật CRL" },
    { text: "Verify chain là gốc của HTTPS",                    sub: "Sai 1 mắt xích → trình duyệt báo NET::ERR_CERT_AUTHORITY_INVALID" },
  ], { fontSize: 12 }), {
    x: 0.5, y: 2.0, w: 5.3, h: 3.0,
    fontSize: 12, fontFace: FONT, color: C.text,
    paraSpaceAfter: 6, margin: 0,
  });

  // Right: TLS chain diagram
  const dx = 6.2, dy = 1.5;
  s.addText("Chain of trust", {
    x: dx, y: dy, w: 3.3, h: 0.3,
    fontSize: 11, fontFace: FONT, bold: true, color: C.muted,
    align: "center", charSpacing: 4, margin: 0,
  });

  const chain = [
    { label: "Root CA",     color: C.navy,   tag: "self-signed" },
    { label: "End-entity",  color: C.teal,   tag: "myshop.com" },
    { label: "Browser",     color: C.midnight, tag: "verify chain" },
  ];
  chain.forEach((c, i) => {
    const y = dy + 0.5 + i * 1.05;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: dx + 0.3, y, w: 2.7, h: 0.75, rectRadius: 0.08,
      fill: { color: c.color }, line: { type: "none" },
      shadow: shadow(),
    });
    s.addText(c.label, {
      x: dx + 0.3, y: y + 0.08, w: 2.7, h: 0.32,
      fontSize: 14, fontFace: FONT, bold: true, color: C.white,
      align: "center", margin: 0,
    });
    s.addText(c.tag, {
      x: dx + 0.3, y: y + 0.42, w: 2.7, h: 0.25,
      fontSize: 9, fontFace: FONT, color: C.ice, italic: true,
      align: "center", margin: 0,
    });
    if (i < chain.length - 1) {
      s.addShape(pres.shapes.LINE, {
        x: dx + 1.65, y: y + 0.78, w: 0, h: 0.22,
        line: { color: C.teal, width: 2, endArrowType: "triangle" },
      });
    }
  });
}

// ── 3. X.509 là gì? ──────────────────────────────────────────────────────────
{
  const s = newContentSlide("X.509 là gì?", "Chuẩn ITU-T cho public-key certificate · RFC 5280", 3, TOTAL);

  // Left: definition
  card(s, 0.5, 1.45, 4.4, 3.55, { accent: C.navy });
  s.addText("Định nghĩa", {
    x: 0.7, y: 1.6, w: 4.0, h: 0.32,
    fontSize: 14, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });
  s.addText(bullets([
    { text: "Chuẩn ITU-T X.509 v3 · RFC 5280", sub: "Phổ biến từ 1988 đến nay" },
    { text: "Định dạng public-key certificate",  sub: "Bind public key ↔ identity" },
    { text: "Identity = ai sở hữu khóa?",        sub: "Domain · người · service · device" },
    { text: "Cert được CA ký bằng private key",  sub: "Bảo đảm tính toàn vẹn + nguồn gốc" },
    { text: "Encode chuẩn ASN.1 DER / PEM",      sub: "Trao đổi giữa hệ thống không phụ thuộc OS" },
  ], { fontSize: 11 }), {
    x: 0.7, y: 1.95, w: 4.0, h: 3.0,
    fontSize: 11, fontFace: FONT, color: C.text,
    paraSpaceAfter: 6, margin: 0,
  });

  // Right: use cases grid
  card(s, 5.1, 1.45, 4.4, 3.55, { accent: C.teal });
  s.addText("Dùng để làm gì?", {
    x: 5.3, y: 1.6, w: 4.0, h: 0.32,
    fontSize: 14, fontFace: FONT, bold: true, color: C.teal, margin: 0,
  });

  const uses = [
    { icon: "🌐", label: "TLS / HTTPS",         desc: "Web server cert · đồ án focus" },
    { icon: "✉", label: "S/MIME email",         desc: "Ký + mã hoá email" },
    { icon: "💾", label: "Code signing",         desc: "Verifies binary publisher" },
    { icon: "🔐", label: "Client auth (mTLS)",   desc: "Mutual TLS · zero-trust" },
    { icon: "🆔", label: "CCCD / e-ID Việt Nam", desc: "Định danh điện tử quốc gia" },
  ];
  uses.forEach((u, i) => {
    const y = 1.95 + i * 0.58;
    s.addText(u.icon, {
      x: 5.3, y, w: 0.45, h: 0.45,
      fontSize: 20, align: "center", valign: "middle", margin: 0,
    });
    s.addText(u.label, {
      x: 5.8, y, w: 3.7, h: 0.24,
      fontSize: 12, fontFace: FONT, bold: true, color: C.text, margin: 0,
    });
    s.addText(u.desc, {
      x: 5.8, y: y + 0.24, w: 3.7, h: 0.24,
      fontSize: 9, fontFace: FONT, color: C.muted, margin: 0,
    });
  });
}

// ── 4. Cấu trúc Certificate ──────────────────────────────────────────────────
{
  const s = newContentSlide("Cấu trúc Certificate X.509", "TBSCertificate + Signature Algorithm + Signature", 4, TOTAL);

  // Outer cert box
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.5, y: 1.45, w: 9, h: 3.6,
    fill: { color: C.card },
    line: { color: C.navy, width: 2 },
    shadow: shadow(),
  });
  s.addText("X.509 Certificate", {
    x: 0.6, y: 1.55, w: 8.8, h: 0.3,
    fontSize: 11, fontFace: FONT, bold: true, color: C.navy,
    charSpacing: 4, margin: 0,
  });

  // TBSCertificate inner box
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.7, y: 1.95, w: 6.0, h: 2.95,
    fill: { color: C.bg }, line: { color: C.teal, width: 1.5 },
  });
  s.addText("TBSCertificate (vùng được ký)", {
    x: 0.8, y: 2.0, w: 5.8, h: 0.28,
    fontSize: 10, fontFace: FONT, bold: true, color: C.teal,
    charSpacing: 3, margin: 0,
  });

  const tbsFields = [
    { k: "Version",          v: "v3 (giá trị 2)" },
    { k: "Serial Number",    v: "Số ngẫu nhiên · unique trong CA" },
    { k: "Signature Algo",   v: "Vd: sha256WithRSAEncryption" },
    { k: "Issuer DN",        v: "Tên CA ký cert này" },
    { k: "Validity",         v: "notBefore + notAfter" },
    { k: "Subject DN",       v: "Tên chủ thể (CN=myshop.com)" },
    { k: "SubjectPublicKey", v: "Public key + algorithm OID" },
    { k: "Extensions v3",    v: "SAN · KeyUsage · EKU · BC · CRL DP · AIA · SKI · AKI" },
  ];
  tbsFields.forEach((f, i) => {
    const y = 2.3 + i * 0.31;
    s.addText(f.k + ":", {
      x: 0.85, y, w: 1.7, h: 0.28,
      fontSize: 9.5, fontFace: MONO, bold: true,
      color: i === tbsFields.length - 1 ? C.danger : C.navy, margin: 0,
    });
    s.addText(f.v, {
      x: 2.55, y, w: 4.1, h: 0.28,
      fontSize: 9, fontFace: FONT, color: C.text, margin: 0,
    });
  });

  // Right side: signature components
  s.addShape(pres.shapes.RECTANGLE, {
    x: 6.85, y: 1.95, w: 2.5, h: 1.4,
    fill: { color: C.bg }, line: { color: C.warning, width: 1.5 },
  });
  s.addText("Signature Algorithm", {
    x: 6.95, y: 2.05, w: 2.3, h: 0.25,
    fontSize: 9.5, fontFace: FONT, bold: true, color: C.warning,
    charSpacing: 2, margin: 0,
  });
  s.addText("Lặp lại algorithm đã khai báo trong TBSCertificate (chống tampering)", {
    x: 6.95, y: 2.35, w: 2.3, h: 0.95,
    fontSize: 9, fontFace: FONT, color: C.text, margin: 0,
  });

  s.addShape(pres.shapes.RECTANGLE, {
    x: 6.85, y: 3.5, w: 2.5, h: 1.4,
    fill: { color: C.bg }, line: { color: C.danger, width: 1.5 },
  });
  s.addText("Signature Value", {
    x: 6.95, y: 3.6, w: 2.3, h: 0.25,
    fontSize: 9.5, fontFace: FONT, bold: true, color: C.danger,
    charSpacing: 2, margin: 0,
  });
  s.addText("Ký TBSCertificate bằng private key của Issuer (CA). Verifier dùng public key của CA để check.", {
    x: 6.95, y: 3.9, w: 2.3, h: 0.95,
    fontSize: 9, fontFace: FONT, color: C.text, margin: 0,
  });

  // Footer note
  s.addText("Sửa 1 bit bất kỳ trong TBSCertificate → signature verify FAIL → cert bị reject.", {
    x: 0.5, y: 5.10, w: 9, h: 0.25,
    fontSize: 10, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0,
  });
}

// ── 5. Mô hình tin cậy: Root CA → Trust Store → Client ───────────────────────
{
  const s = newContentSlide("Mô hình tin cậy", "Root CA · Trust Store · Client verify · 3 bước", 5, TOTAL);

  // Three big boxes horizontal
  const flow = [
    {
      title: "ROOT CA", sub: "Self-signed cert\nissuer == subject",
      color: C.navy, bgTag: "Tạo trust anchor",
    },
    {
      title: "TRUST STORE", sub: "Chứa cert Root CA\ntin cậy trước",
      color: C.teal, bgTag: "Distributed pre-trust",
    },
    {
      title: "CLIENT", sub: "Verify cert end-entity\nbằng Root CA pubkey",
      color: C.midnight, bgTag: "Verify on demand",
    },
  ];

  const bw = 2.65, gap = 0.4, baseX = 0.55;
  flow.forEach((f, i) => {
    const x = baseX + i * (bw + gap), y = 1.7;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y, w: bw, h: 1.85, rectRadius: 0.12,
      fill: { color: f.color }, line: { type: "none" }, shadow: shadow(),
    });
    s.addText(f.title, {
      x, y: y + 0.25, w: bw, h: 0.45,
      fontSize: 18, fontFace: FONT, bold: true, color: C.white,
      align: "center", charSpacing: 4, margin: 0,
    });
    s.addText(f.sub, {
      x: x + 0.1, y: y + 0.78, w: bw - 0.2, h: 0.7,
      fontSize: 11, fontFace: FONT, color: C.ice,
      align: "center", margin: 0,
    });
    // Step number bubble
    s.addShape(pres.shapes.OVAL, {
      x: x + bw - 0.4, y: y - 0.15, w: 0.5, h: 0.5,
      fill: { color: C.white }, line: { color: f.color, width: 2 },
    });
    s.addText(String(i + 1), {
      x: x + bw - 0.4, y: y - 0.15, w: 0.5, h: 0.5,
      fontSize: 16, fontFace: FONT, bold: true, color: f.color,
      align: "center", valign: "middle", margin: 0,
    });
    // Arrow to next
    if (i < flow.length - 1) {
      s.addShape(pres.shapes.LINE, {
        x: x + bw, y: y + 0.95, w: gap, h: 0,
        line: { color: C.text, width: 2.5, endArrowType: "triangle" },
      });
    }
  });

  // Three-step labels under
  const labels = [
    "Tự ký cert · phân phối public key như trust anchor",
    "OS / browser / app cài sẵn cert Root CA tin cậy",
    "Browser duyệt cert server · check chain ngược về Root",
  ];
  labels.forEach((lb, i) => {
    const x = baseX + i * (bw + gap), y = 3.75;
    s.addText(`Bước ${i + 1}`, {
      x, y, w: bw, h: 0.25,
      fontSize: 9, fontFace: FONT, bold: true, color: C.teal,
      align: "center", charSpacing: 3, margin: 0,
    });
    s.addText(lb, {
      x, y: y + 0.25, w: bw, h: 0.75,
      fontSize: 10, fontFace: FONT, color: C.text,
      align: "center", margin: 0,
    });
  });

  // Footer
  s.addText("Trong đồ án: trust store = thư mục certs/trust_store/root_ca.crt — sync mỗi lần Publish.", {
    x: 0.5, y: 4.85, w: 9, h: 0.3,
    fontSize: 11, fontFace: FONT, italic: true, color: C.danger,
    align: "center", margin: 0,
  });
}

// ── 6. Mục tiêu ──────────────────────────────────────────────────────────────
{
  const s = newContentSlide("Mục tiêu đồ án", "20 yêu cầu chức năng + 1 lưu ý bảo mật", 6, TOTAL);

  // 3 columns: A / B / C
  const cols = [
    { title: "Admin (A.1 – A.11)", color: C.navy, items: [
      "Đăng nhập + đổi mật khẩu",
      "Cấu hình hệ thống",
      "Sinh Root CA keypair + cert",
      "Duyệt CSR + phát hành cert",
      "Revoke + Renew cert",
      "Duyệt yêu cầu thu hồi",
      "Publish CRL",
      "Audit log",
    ]},
    { title: "Customer (B.1 – B.9)", color: C.teal, items: [
      "Đăng ký + đăng nhập + đổi pw",
      "Sinh keypair RSA",
      "Submit CSR cho domain",
      "Xem chi tiết + tải cert",
      "Yêu cầu thu hồi cert",
      "Tra cứu CRL công khai",
      "Upload cert ngoài + verify 5 bước",
    ]},
    { title: "Lưu ý C — Bảo mật", color: C.midnight, items: [
      "Encrypt-at-rest cho private key",
      "AES-256-GCM + AAD bind theo row",
      "Master key trong master.key",
      "Hash password bằng scrypt",
      "BOLA guard mọi customer query",
      "Audit log tamper-evident",
    ]},
  ];

  const cardW = 2.95, cardH = 3.6, gap = 0.13;
  cols.forEach((col, i) => {
    const x = 0.5 + i * (cardW + gap);
    card(s, x, 1.45, cardW, cardH, { accent: col.color });
    s.addText(col.title, {
      x: x + 0.2, y: 1.55, w: cardW - 0.4, h: 0.45,
      fontSize: 14, fontFace: FONT, bold: true, color: col.color, margin: 0,
    });
    s.addText(bullets(col.items, { fontSize: 11 }), {
      x: x + 0.2, y: 2.05, w: cardW - 0.4, h: 2.9,
      fontSize: 11, fontFace: FONT, color: C.text,
      paraSpaceAfter: 4, margin: 0,
    });
  });
}

// ── 7. Phạm vi & giới hạn ────────────────────────────────────────────────────
{
  const s = newContentSlide("Phạm vi & giới hạn", "Trong scope vs out of scope", 7, TOTAL);

  card(s, 0.5, 1.45, 4.4, 3.6, { accent: C.success });
  s.addText("✓  Trong phạm vi", {
    x: 0.7, y: 1.6, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT, bold: true, color: C.success, margin: 0,
  });
  s.addText(bullets([
    "Single Root CA (không hierarchy)",
    "TLS server certificate (serverAuth)",
    "Workflow CSR + revoke đầy đủ",
    "CRL + OCSP responder (DB-backed)",
    "GUI Tkinter + SQLite local",
    "Encrypt-at-rest cho private key",
    "Audit log + BOLA guard",
  ], { fontSize: 12 }), {
    x: 0.7, y: 2.0, w: 4.0, h: 2.9,
    fontSize: 12, fontFace: FONT, color: C.text,
    paraSpaceAfter: 5, margin: 0,
  });

  card(s, 5.1, 1.45, 4.4, 3.6, { accent: C.danger });
  s.addText("✗  Ngoài phạm vi", {
    x: 5.3, y: 1.6, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT, bold: true, color: C.danger, margin: 0,
  });
  s.addText(bullets([
    "Multi-tier CA (Intermediate CA)",
    "Hardware HSM cho key storage",
    "ACME protocol (Let's Encrypt-style)",
    "S/MIME + code-signing cert",
    "Cluster + multi-tenant",
    "Web client (chỉ desktop GUI)",
    "Cert Transparency log",
  ], { fontSize: 12 }), {
    x: 5.3, y: 2.0, w: 4.0, h: 2.9,
    fontSize: 12, fontFace: FONT, color: C.text,
    paraSpaceAfter: 5, margin: 0,
  });
}

// ── 8. Tech stack ────────────────────────────────────────────────────────────
{
  const s = newContentSlide("Tech stack", "Stack đơn giản, chạy offline, không phụ thuộc cloud", 8, TOTAL);

  const stack = [
    { icon: "🐍", name: "Python 3.14",     desc: "Ngôn ngữ chính · type hints · pathlib · dataclass" },
    { icon: "🪟", name: "Tkinter + ttk",   desc: "GUI desktop · style theme Montserrat · scrollspy" },
    { icon: "🗃", name: "SQLite",          desc: "Single-file DB · WAL mode · atomic transaction" },
    { icon: "🔐", name: "cryptography",    desc: "RSA · PKCS#10 · X.509 · AES-256-GCM · scrypt" },
    { icon: "🌐", name: "http.server",     desc: "CRL HTTP server (8889) + OCSP responder (8888)" },
    { icon: "🧪", name: "unittest",        desc: "70 test cases · 8 module · BOLA + race condition" },
  ];

  const cardW = 4.4, cardH = 1.05, gapY = 0.15;
  stack.forEach((it, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.5 + col * (cardW + 0.2);
    const y = 1.55 + row * (cardH + gapY);
    card(s, x, y, cardW, cardH);
    s.addText(it.icon, {
      x: x + 0.15, y: y + 0.18, w: 0.7, h: 0.7,
      fontSize: 28, align: "center", valign: "middle", margin: 0,
    });
    s.addText(it.name, {
      x: x + 0.9, y: y + 0.15, w: cardW - 1.0, h: 0.4,
      fontSize: 14, fontFace: FONT, bold: true, color: C.navy, margin: 0,
    });
    s.addText(it.desc, {
      x: x + 0.9, y: y + 0.55, w: cardW - 1.0, h: 0.45,
      fontSize: 10, fontFace: FONT, color: C.muted, margin: 0,
    });
  });
}

// ── 9. Thư viện chính + code snippets ────────────────────────────────────────
{
  const s = newContentSlide("Thư viện chính + code", "Trích từ src/core/ — code thật, không pseudo", 9, TOTAL);

  // 4 code cards (2x2 grid)
  const cardW = 4.4, cardH = 1.65, gap = 0.15;
  const snippets = [
    {
      title: "Sinh keypair RSA + ký cert",
      file: "core/cert_builder.py",
      lines: [
        { t: "key = rsa.", c: C.white },
        { t: "generate_private_key", c: "97BC62" },
        { t: "(65537, key_size=2048)\n", c: C.white },
        { t: "cert = (x509.", c: C.white },
        { t: "CertificateBuilder", c: "97BC62" },
        { t: "()\n  .subject_name(...).issuer_name(ca.subject)\n  .public_key(pubkey).serial_number(", c: C.white },
        { t: "random_serial_number", c: "97BC62" },
        { t: "())\n  .not_valid_before(now).not_valid_after(exp)\n  .add_extension(SubjectAlternativeName(...))\n  .", c: C.white },
        { t: "sign", c: "F96167" },
        { t: "(ca_private_key, hashes.SHA256()))", c: C.white },
      ],
    },
    {
      title: "Verify CSR signature · proof-of-possession",
      file: "services/csr_admin.py",
      lines: [
        { t: "# Đảm bảo customer thực sự sở hữu private key\n", c: C.ice },
        { t: "csr = x509.", c: C.white },
        { t: "load_pem_x509_csr", c: "97BC62" },
        { t: "(csr_pem)\n", c: C.white },
        { t: "if not csr.", c: C.white },
        { t: "is_signature_valid", c: "F9E795" },
        { t: ":\n    raise CSRAdminError(", c: C.white },
        { t: "\"Invalid CSR signature\"", c: "97BC62" },
        { t: ")\n\n# Build cert end-entity rồi ký bằng Root CA key\nissue_certificate(cur, csr=csr, validity_days=...)", c: C.white },
      ],
    },
    {
      title: "AES-256-GCM encrypt-at-rest (AAD bind id)",
      file: "core/encryption.py",
      lines: [
        { t: "# AAD ngăn copy ciphertext sang row khác\n", c: C.ice },
        { t: "aad   = f", c: C.white },
        { t: "\"customer_keys:{row_id}\"", c: "97BC62" },
        { t: ".encode()\n", c: C.white },
        { t: "nonce = secrets.", c: C.white },
        { t: "token_bytes", c: "F9E795" },
        { t: "(12)\n", c: C.white },
        { t: "ct    = ", c: C.white },
        { t: "AESGCM", c: "97BC62" },
        { t: "(master_key).", c: C.white },
        { t: "encrypt", c: "F9E795" },
        { t: "(nonce, pk_bytes, aad)\n\n", c: C.white },
        { t: "# decrypt sai AAD → InvalidTag", c: C.ice },
      ],
    },
    {
      title: "scrypt password hash · self-describing",
      file: "core/encryption.py",
      lines: [
        { t: "salt  = secrets.token_bytes(16)\n", c: C.white },
        { t: "derived = hashlib.", c: C.white },
        { t: "scrypt", c: "97BC62" },
        { t: "(\n    password.encode(), salt=salt,\n    n=", c: C.white },
        { t: "16384", c: "F9E795" },
        { t: ", r=", c: C.white },
        { t: "8", c: "F9E795" },
        { t: ", p=", c: C.white },
        { t: "1", c: "F9E795" },
        { t: ", dklen=", c: C.white },
        { t: "32", c: "F9E795" },
        { t: ")\nreturn f", c: C.white },
        { t: "\"scrypt${N}${r}${p}${salt}${derived}\"", c: "97BC62" },
      ],
    },
  ];

  snippets.forEach((sn, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.5 + col * (cardW + gap);
    const y = 1.5 + row * (cardH + gap);
    // dark code card
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: cardW, h: cardH,
      fill: { color: C.midnight }, line: { type: "none" },
      shadow: shadow(),
    });
    // Top accent
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: cardW, h: 0.05,
      fill: { color: C.teal }, line: { type: "none" },
    });
    // Title
    s.addText(sn.title, {
      x: x + 0.15, y: y + 0.1, w: cardW - 0.3, h: 0.28,
      fontSize: 11, fontFace: FONT, bold: true, color: C.white, margin: 0,
    });
    // File path
    s.addText(`# ${sn.file}`, {
      x: x + 0.15, y: y + 0.38, w: cardW - 0.3, h: 0.22,
      fontSize: 9, fontFace: MONO, color: C.teal, italic: true, margin: 0,
    });
    // Code
    const richText = sn.lines.map(ln => ({
      text: ln.t,
      options: { color: ln.c },
    }));
    s.addText(richText, {
      x: x + 0.15, y: y + 0.62, w: cardW - 0.3, h: cardH - 0.75,
      fontSize: 9, fontFace: MONO, valign: "top", margin: 0,
    });
  });

  s.addText("Tất cả primitive crypto từ stdlib `hashlib.scrypt` + `cryptography` (pyca/cryptography — backed by OpenSSL).", {
    x: 0.5, y: 5.00, w: 9, h: 0.25,
    fontSize: 9, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0,
  });
}

// ── 10. Kiến trúc layer ──────────────────────────────────────────────────────
{
  const s = newContentSlide("Kiến trúc theo layer", "Tách bạch UI · services · core · db · infra", 10, TOTAL);

  const layers = [
    { name: "ui/",       desc: "Tkinter views · admin + customer + widgets",   color: C.teal,    detail: "13 view files · 1 reusable modal helper" },
    { name: "services/", desc: "Business logic · auth · CA admin · CSR · CRL", color: C.navy,    detail: "12 modules · pure function · raise typed errors" },
    { name: "core/",     desc: "Crypto primitive · AES-GCM · scrypt · X.509",  color: C.midnight,detail: "Stateless · không chạm DB" },
    { name: "db/",       desc: "SQLite schema · migration · DAO",              color: "047857", detail: "9 bảng · WAL · foreign key ON" },
    { name: "infra/",    desc: "CRL/OCSP HTTP server · trust store sync",      color: "B45309", detail: "Chạy ngầm trong cùng process" },
  ];

  const lh = 0.62;
  layers.forEach((l, i) => {
    const y = 1.55 + i * (lh + 0.1);
    // Layer name pill
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.5, y, w: 1.8, h: lh, rectRadius: 0.06,
      fill: { color: l.color }, line: { type: "none" }, shadow: shadow(),
    });
    s.addText(l.name, {
      x: 0.5, y, w: 1.8, h: lh,
      fontSize: 14, fontFace: MONO, bold: true, color: C.white,
      align: "center", valign: "middle", margin: 0,
    });
    // Description
    s.addText(l.desc, {
      x: 2.5, y: y + 0.04, w: 7.1, h: 0.28,
      fontSize: 12, fontFace: FONT, bold: true, color: C.text, margin: 0,
    });
    s.addText(l.detail, {
      x: 2.5, y: y + 0.33, w: 7.1, h: 0.24,
      fontSize: 10, fontFace: FONT, color: C.muted, margin: 0,
    });
  });

  s.addText("Mỗi layer trên chỉ gọi xuống layer dưới — UI không chạm crypto trực tiếp, service không viết SQL inline.", {
    x: 0.5, y: 4.95, w: 9, h: 0.3,
    fontSize: 10, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0,
  });
}

// ── 11. DB schema ────────────────────────────────────────────────────────────
{
  const s = newContentSlide("Database schema", "9 bảng chính · quan hệ rõ ràng · FK ON", 11, TOTAL);

  const tables = [
    { name: "users",                desc: "username · pw_hash · role · created_at" },
    { name: "root_ca",              desc: "id · cn · serial · enc_private_key · is_active" },
    { name: "customer_keys",        desc: "owner_id · name · key_size · enc_private_key" },
    { name: "csr_requests",         desc: "requester · key_id · cn · san · status" },
    { name: "issued_certs",         desc: "owner · csr · cert_pem · serial · validity" },
    { name: "revocation_requests",  desc: "cert · requester · reason · status · reviewed_by" },
    { name: "crl_publications",     desc: "crl_pem · revoked_serials · published_at" },
    { name: "external_certs",       desc: "owner · cert_pem · uploaded_at · note" },
    { name: "audit_log",            desc: "actor · action · target · details_json · ts" },
  ];

  const cardW = 2.95, cardH = 0.92, gap = 0.13;
  tables.forEach((t, i) => {
    const col = i % 3, row = Math.floor(i / 3);
    const x = 0.5 + col * (cardW + gap);
    const y = 1.55 + row * (cardH + 0.18);
    card(s, x, y, cardW, cardH, { accent: C.teal });
    s.addText(t.name, {
      x: x + 0.18, y: y + 0.10, w: cardW - 0.3, h: 0.35,
      fontSize: 13, fontFace: MONO, bold: true, color: C.navy, margin: 0,
    });
    s.addText(t.desc, {
      x: x + 0.18, y: y + 0.45, w: cardW - 0.3, h: 0.42,
      fontSize: 9, fontFace: FONT, color: C.muted, margin: 0,
    });
  });

  s.addText("Encrypted columns: root_ca.enc_private_key, customer_keys.enc_private_key (AES-256-GCM)", {
    x: 0.5, y: 4.95, w: 9, h: 0.3,
    fontSize: 10, fontFace: FONT, italic: true, color: C.danger, align: "center", margin: 0,
  });
}

// ── 12. Bootstrap (A.1-3) ────────────────────────────────────────────────────
{
  const s = newContentSlide("Bootstrap · A.1 – A.3", "First-run init · login · cấu hình hệ thống", 12, TOTAL);

  // Left column: First-run flow
  s.addText("First-run flow", {
    x: 0.5, y: 1.5, w: 4.4, h: 0.32,
    fontSize: 14, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });

  const steps = [
    "Tạo SQLite + chạy migration",
    "Sinh master.key 32 bytes (CSPRNG)",
    "Seed system_config defaults",
    "Tạo admin / Admin@123 (bắt đổi pw)",
  ];
  steps.forEach((st, i) => {
    const y = 1.95 + i * 0.45;
    s.addShape(pres.shapes.OVAL, {
      x: 0.5, y, w: 0.32, h: 0.32,
      fill: { color: C.teal }, line: { type: "none" },
    });
    s.addText(String(i + 1), {
      x: 0.5, y, w: 0.32, h: 0.32,
      fontSize: 11, fontFace: FONT, bold: true, color: C.white,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(st, {
      x: 0.95, y: y + 0.02, w: 3.9, h: 0.32,
      fontSize: 12, fontFace: FONT, color: C.text, margin: 0,
    });
  });

  // Right: Code snippet
  card(s, 5.1, 1.5, 4.4, 3.4, { fill: C.midnight });
  s.addText("scrypt password hash", {
    x: 5.25, y: 1.6, w: 4.1, h: 0.3,
    fontSize: 10, fontFace: FONT, color: C.teal, bold: true,
    charSpacing: 3, margin: 0,
  });
  s.addText([
    { text: "# core/passwords.py\n", options: { color: C.ice } },
    { text: "salt = secrets.token_bytes(16)\n", options: { color: "FFFFFF" } },
    { text: "key  = scrypt(pw, salt, ", options: { color: "FFFFFF" } },
    { text: "N=16384,\n            r=8, p=1, dklen=32", options: { color: "1C7293" } },
    { text: ")\n", options: { color: "FFFFFF" } },
    { text: "hash = f", options: { color: "FFFFFF" } },
    { text: "\"scrypt${N}${r}${p}${salt}${key}\"", options: { color: "97BC62" } },
    { text: "\n\n", options: {} },
    { text: "# Verify supports legacy hashes by\n", options: { color: C.ice } },
    { text: "# parsing N/r/p from hash prefix.", options: { color: C.ice } },
  ], {
    x: 5.25, y: 1.95, w: 4.1, h: 2.9,
    fontSize: 11, fontFace: MONO, color: C.white, valign: "top", margin: 0,
  });
}

// ── 13. Root CA (A.4-5) ──────────────────────────────────────────────────────
{
  const s = newContentSlide("Root CA · A.4 – A.5", "Sinh keypair · cert self-signed · publish trust store", 13, TOTAL);

  const flow = [
    { num: "1", title: "Generate RSA",        desc: "key_size 2048/3072/4096 · CSPRNG" },
    { num: "2", title: "Build self-sign cert",desc: "issuer = subject · CA=true · path_len=0" },
    { num: "3", title: "Encrypt private key", desc: "AES-256-GCM · AAD=\"root_ca\" · master.key" },
    { num: "4", title: "INSERT root_ca",      desc: "is_active=1 · deactivate cái cũ nếu rotate" },
    { num: "5", title: "Publish trust store", desc: "Ghi certs/trust_store/root_ca.crt (PEM)" },
  ];

  flow.forEach((f, i) => {
    const x = 0.5 + i * 1.85, y = 1.7;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y, w: 1.7, h: 2.5, rectRadius: 0.08,
      fill: { color: C.card },
      line: { color: C.border, width: 0.75 },
      shadow: shadow(),
    });
    s.addShape(pres.shapes.OVAL, {
      x: x + 0.65, y: y + 0.2, w: 0.4, h: 0.4,
      fill: { color: C.navy }, line: { type: "none" },
    });
    s.addText(f.num, {
      x: x + 0.65, y: y + 0.2, w: 0.4, h: 0.4,
      fontSize: 14, fontFace: FONT, bold: true, color: C.white,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(f.title, {
      x: x + 0.1, y: y + 0.75, w: 1.5, h: 0.6,
      fontSize: 11, fontFace: FONT, bold: true, color: C.navy,
      align: "center", margin: 0,
    });
    s.addText(f.desc, {
      x: x + 0.1, y: y + 1.35, w: 1.5, h: 1.0,
      fontSize: 9, fontFace: FONT, color: C.muted,
      align: "center", margin: 0,
    });
    if (i < flow.length - 1) {
      s.addShape(pres.shapes.LINE, {
        x: x + 1.7, y: y + 1.25, w: 0.15, h: 0,
        line: { color: C.teal, width: 2, endArrowType: "triangle" },
      });
    }
  });

  s.addText("Mọi private key trong DB là ciphertext — master.key tách rời và KHÔNG bao giờ commit Git.", {
    x: 0.5, y: 4.55, w: 9, h: 0.4,
    fontSize: 11, fontFace: FONT, italic: true, color: C.danger,
    align: "center", margin: 0,
  });
}

// ── 14. Customer onboarding (B.1-3) ──────────────────────────────────────────
{
  const s = newContentSlide("Customer onboarding · B.1 – B.3", "Đăng ký · đăng nhập · đổi mật khẩu", 14, TOTAL);

  const features = [
    { tag: "B.1", title: "Đăng ký Customer", desc: "Username unique · password ≥ 8 ký tự · scrypt hash trước khi INSERT" },
    { tag: "B.2", title: "Đăng nhập",        desc: "Verify hash · attach session.id + username + role · audit LOGIN_SUCCESS / FAILED" },
    { tag: "B.3", title: "Đổi mật khẩu",     desc: "Check pw cũ · validate pw mới · hash + UPDATE · audit PASSWORD_CHANGED" },
  ];

  features.forEach((f, i) => {
    const y = 1.55 + i * 1.05;
    card(s, 0.5, y, 9, 0.95, { accent: C.teal });
    pill(s, 0.65, y + 0.18, 0.55, 0.32, f.tag, C.white, C.teal);
    s.addText(f.title, {
      x: 1.35, y: y + 0.17, w: 3.5, h: 0.35,
      fontSize: 14, fontFace: FONT, bold: true, color: C.navy, margin: 0,
    });
    s.addText(f.desc, {
      x: 1.35, y: y + 0.50, w: 7.8, h: 0.45,
      fontSize: 11, fontFace: FONT, color: C.text, margin: 0,
    });
  });

  s.addText("Admin chỉ được tạo qua bootstrap. Customer tự đăng ký + tự login luôn sau register cho UX mượt.", {
    x: 0.5, y: 4.85, w: 9, h: 0.3,
    fontSize: 10, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0,
  });
}

// ── 15. Keypair (B.4) ────────────────────────────────────────────────────────
{
  const s = newContentSlide("Keypair của Customer · B.4", "Sinh RSA · mã hoá lưu DB · public xuất PEM", 15, TOTAL);

  // Left: encryption diagram
  s.addText("Encrypt-at-rest pipeline", {
    x: 0.5, y: 1.5, w: 4.4, h: 0.3,
    fontSize: 13, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });

  const pipe = [
    { label: "RSA private key", color: C.warning },
    { label: "AES-256-GCM",     color: C.teal,    sub: "key = master.key" },
    { label: "AAD bind id",     color: C.navy,    sub: "\"customer_keys:{id}\"" },
    { label: "INSERT enc_pk",   color: C.midnight },
  ];
  pipe.forEach((p, i) => {
    const y = 1.95 + i * 0.65;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.5, y, w: 4.4, h: 0.55, rectRadius: 0.06,
      fill: { color: p.color }, line: { type: "none" },
    });
    s.addText(p.label, {
      x: 0.7, y: y + 0.05, w: 4.0, h: 0.28,
      fontSize: 12, fontFace: FONT, bold: true, color: C.white, margin: 0,
    });
    if (p.sub) {
      s.addText(p.sub, {
        x: 0.7, y: y + 0.30, w: 4.0, h: 0.25,
        fontSize: 9, fontFace: MONO, color: C.ice, margin: 0,
      });
    }
    if (i < pipe.length - 1) {
      s.addShape(pres.shapes.LINE, {
        x: 2.7, y: y + 0.55, w: 0, h: 0.1,
        line: { color: C.muted, width: 1.5, endArrowType: "triangle" },
      });
    }
  });

  // Right: Why AAD?
  card(s, 5.1, 1.5, 4.4, 3.4, { accent: C.navy });
  s.addText("Vì sao AAD bind id?", {
    x: 5.3, y: 1.65, w: 4.0, h: 0.32,
    fontSize: 13, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });
  s.addText(bullets([
    { text: "AAD = Additional Authenticated Data", sub: "Không nằm trong ciphertext nhưng phải khớp khi decrypt" },
    { text: "Nếu attacker copy enc_pk sang row khác", sub: "AAD mới = \"customer_keys:99\" ≠ AAD lúc encrypt → tag fail" },
    { text: "Tag GCM check tampering bit-level",     sub: "Đổi 1 bit ciphertext cũng fail" },
    { text: "Master key sống ngoài DB",              sub: "Dump DB ≠ attacker đọc được key" },
  ], { fontSize: 11 }), {
    x: 5.3, y: 2.05, w: 4.0, h: 2.85,
    fontSize: 11, fontFace: FONT, color: C.text,
    paraSpaceAfter: 4, margin: 0,
  });
}

// ── 16. CSR (B.5-6) ──────────────────────────────────────────────────────────
{
  const s = newContentSlide("Yêu cầu cấp chứng nhận · B.5", "PKCS#10 · proof of possession · SAN chuẩn TLS", 16, TOTAL);

  // Top: CSR structure
  card(s, 0.5, 1.5, 9, 1.3, { accent: C.teal });
  s.addText("CSR — PKCS#10 chứa gì?", {
    x: 0.65, y: 1.6, w: 8.7, h: 0.3,
    fontSize: 13, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });
  const fields = ["Subject (CN, O)", "Public key", "SAN extension", "Signature (RSA-SHA256)"];
  fields.forEach((f, i) => {
    const x = 0.65 + i * 2.18;
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: 2.0, w: 2.05, h: 0.65,
      fill: { color: C.bg }, line: { color: C.border, width: 0.5 },
    });
    s.addText(f, {
      x, y: 2.0, w: 2.05, h: 0.65,
      fontSize: 10, fontFace: FONT, color: C.text, bold: true,
      align: "center", valign: "middle", margin: 0,
    });
  });

  // Bottom: 2 cards
  card(s, 0.5, 3.0, 4.4, 1.95, { accent: C.navy });
  s.addText("Proof of Possession", {
    x: 0.7, y: 3.15, w: 4.0, h: 0.3,
    fontSize: 13, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });
  s.addText(bullets([
    "CSR được ký bằng private key của customer",
    "Admin verify signature trước khi approve",
    "Đảm bảo customer thực sự sở hữu key",
  ], { fontSize: 11 }), {
    x: 0.7, y: 3.5, w: 4.0, h: 1.4,
    fontSize: 11, fontFace: FONT, color: C.text,
    paraSpaceAfter: 4, margin: 0,
  });

  card(s, 5.1, 3.0, 4.4, 1.95, { accent: C.teal });
  s.addText("SAN best practice", {
    x: 5.3, y: 3.15, w: 4.0, h: 0.3,
    fontSize: 13, fontFace: FONT, bold: true, color: C.navy, margin: 0,
  });
  s.addText(bullets([
    "CN tự thêm vào SAN nếu user quên",
    "Multiple domain trong 1 cert (www, api...)",
    "Chuẩn TLS hiện đại bỏ check CN, chỉ check SAN",
  ], { fontSize: 11 }), {
    x: 5.3, y: 3.5, w: 4.0, h: 1.4,
    fontSize: 11, fontFace: FONT, color: C.text,
    paraSpaceAfter: 4, margin: 0,
  });
}

// ── 17. Approve CSR (A.6-7) ──────────────────────────────────────────────────
{
  const s = newContentSlide("Duyệt CSR & Phát hành Cert · A.6 – A.7", "Pipeline 5 bước · atomic transaction", 17, TOTAL);

  const steps = [
    { num: "1", t: "Verify CSR sig",     d: "Proof of possession" },
    { num: "2", t: "Load Root CA",       d: "Decrypt private key" },
    { num: "3", t: "Build end-entity",   d: "SAN · BC=false · KU · EKU" },
    { num: "4", t: "Sign SHA-256",       d: "rsa_pss / pkcs1v15" },
    { num: "5", t: "Atomic INSERT",      d: "+ UPDATE csr.status" },
  ];

  steps.forEach((st, i) => {
    const x = 0.5 + i * 1.85, y = 1.55;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y, w: 1.7, h: 1.7, rectRadius: 0.08,
      fill: { color: C.card },
      line: { color: C.teal, width: 1 },
      shadow: shadow(),
    });
    s.addShape(pres.shapes.OVAL, {
      x: x + 0.6, y: y + 0.18, w: 0.5, h: 0.5,
      fill: { color: C.teal }, line: { type: "none" },
    });
    s.addText(st.num, {
      x: x + 0.6, y: y + 0.18, w: 0.5, h: 0.5,
      fontSize: 16, fontFace: FONT, bold: true, color: C.white,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(st.t, {
      x: x + 0.1, y: y + 0.78, w: 1.5, h: 0.32,
      fontSize: 11, fontFace: FONT, bold: true, color: C.navy,
      align: "center", margin: 0,
    });
    s.addText(st.d, {
      x: x + 0.1, y: y + 1.10, w: 1.5, h: 0.55,
      fontSize: 9, fontFace: FONT, color: C.muted,
      align: "center", margin: 0,
    });
  });

  // Code snippet
  card(s, 0.5, 3.45, 9, 1.5, { fill: C.midnight });
  s.addText("services/csr_admin.py — approve_csr()", {
    x: 0.65, y: 3.55, w: 8.7, h: 0.3,
    fontSize: 10, fontFace: FONT, color: C.teal, bold: true,
    charSpacing: 3, margin: 0,
  });
  s.addText([
    { text: "with db.transaction() as cur:\n", options: { color: C.white } },
    { text: "    if cur.execute(\"SELECT status FROM csr_requests WHERE id=?\", (csr_id,))\n", options: { color: C.white } },
    { text: "           .fetchone()[\"status\"] != ", options: { color: C.white } },
    { text: "\"pending\"", options: { color: "97BC62" } },
    { text: ":\n        raise CSRAdminError(", options: { color: C.white } },
    { text: "\"Already reviewed by another admin\"", options: { color: "97BC62" } },
    { text: ")\n    issue_certificate(cur, ...)   ", options: { color: C.white } },
    { text: "# atomic — race-safe", options: { color: C.ice } },
  ], {
    x: 0.65, y: 3.85, w: 8.7, h: 1.0,
    fontSize: 10, fontFace: MONO, color: C.white, valign: "top", margin: 0,
  });
}

// ── 18. Cert detail ──────────────────────────────────────────────────────────
{
  const s = newContentSlide("Chi tiết Certificate", "Extensions chuẩn TLS server-auth", 18, TOTAL);

  const exts = [
    { name: "BasicConstraints",         val: "CA=false · pathLen=N/A",        c: C.navy },
    { name: "KeyUsage",                 val: "digital_signature + key_encipherment", c: C.teal },
    { name: "ExtendedKeyUsage",         val: "serverAuth (TLS web server)",   c: C.teal },
    { name: "SubjectAlternativeName",   val: "DNS: myshop.com, www.myshop.com, api.myshop.com", c: C.success },
    { name: "CRLDistributionPoints",    val: "http://localhost:8889/crl.pem",  c: C.warning },
    { name: "AuthorityInformationAccess", val: "OCSP: http://localhost:8888/", c: C.warning },
    { name: "SubjectKeyIdentifier",     val: "Hash(SubjectPublicKeyInfo)",     c: C.muted },
    { name: "AuthorityKeyIdentifier",   val: "SKI của Root CA · chain ngược về root", c: C.muted },
  ];

  const cardW = 4.4, cardH = 0.42, gap = 0.08;
  exts.forEach((e, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.5 + col * (cardW + 0.2);
    const y = 1.5 + row * (cardH + gap);
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.06, h: cardH,
      fill: { color: e.c }, line: { type: "none" },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x: x + 0.06, y, w: cardW - 0.06, h: cardH,
      fill: { color: C.card }, line: { color: C.border, width: 0.5 },
    });
    s.addText(e.name, {
      x: x + 0.15, y: y + 0.02, w: cardW - 0.2, h: 0.20,
      fontSize: 10, fontFace: FONT, bold: true, color: e.c, margin: 0,
    });
    s.addText(e.val, {
      x: x + 0.15, y: y + 0.21, w: cardW - 0.2, h: 0.20,
      fontSize: 8.5, fontFace: MONO, color: C.muted, margin: 0,
    });
  });

  s.addText("Customer xem qua tab \"Decoded\" / \"PEM\". Tải về thành .crt để cài lên Nginx / Apache.", {
    x: 0.5, y: 4.9, w: 9, h: 0.3,
    fontSize: 11, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0,
  });
}

// ── 19. Cert lifecycle (A.8) ─────────────────────────────────────────────────
{
  const s = newContentSlide("Cert lifecycle · A.8", "Active → Revoked / Expired · Renew không revoke cũ", 19, TOTAL);

  // State diagram
  const states = [
    { label: "PENDING",  color: C.warning, x: 0.6,  y: 1.7 },
    { label: "ACTIVE",   color: C.success, x: 3.4,  y: 1.7 },
    { label: "REVOKED",  color: C.danger,  x: 6.4,  y: 1.7 },
    { label: "EXPIRED",  color: C.muted,   x: 6.4,  y: 2.85 },
    { label: "RENEWED",  color: C.teal,    x: 3.4,  y: 2.85 },
  ];
  states.forEach(st => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: st.x, y: st.y, w: 2.4, h: 0.7, rectRadius: 0.1,
      fill: { color: st.color }, line: { type: "none" },
      shadow: shadow(),
    });
    s.addText(st.label, {
      x: st.x, y: st.y, w: 2.4, h: 0.7,
      fontSize: 14, fontFace: FONT, bold: true, color: C.white,
      align: "center", valign: "middle", charSpacing: 3, margin: 0,
    });
  });

  // Arrows
  // PENDING → ACTIVE
  s.addShape(pres.shapes.LINE, {
    x: 3.0, y: 2.05, w: 0.4, h: 0,
    line: { color: C.text, width: 2, endArrowType: "triangle" },
  });
  s.addText("approve", { x: 2.95, y: 1.4, w: 1.0, h: 0.25, fontSize: 9, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0 });

  // ACTIVE → REVOKED
  s.addShape(pres.shapes.LINE, {
    x: 5.8, y: 2.05, w: 0.6, h: 0,
    line: { color: C.text, width: 2, endArrowType: "triangle" },
  });
  s.addText("revoke (A.8/A.9)", { x: 5.6, y: 1.4, w: 1.4, h: 0.25, fontSize: 9, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0 });

  // ACTIVE → EXPIRED
  s.addShape(pres.shapes.LINE, {
    x: 4.6, y: 2.4, w: 2.5, h: 0.45,
    line: { color: C.text, width: 2, endArrowType: "triangle" },
  });
  s.addText("not_valid_after", { x: 4.5, y: 2.43, w: 1.6, h: 0.25, fontSize: 9, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0 });

  // ACTIVE → RENEWED
  s.addShape(pres.shapes.LINE, {
    x: 4.6, y: 2.4, w: 0, h: 0.45,
    line: { color: C.text, width: 2, endArrowType: "triangle" },
  });
  s.addText("renew (A.8)", { x: 4.0, y: 2.95, w: 1.5, h: 0.25, fontSize: 9, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0 });

  s.addText(bullets([
    "Renew giữ public key cũ — không cần CSR mới · cert mới có serial khác · cert cũ KHÔNG tự revoke",
    "Direct revoke (admin) skip workflow B.7 — dùng cho incident response",
    "Atomic: nếu cert đã revoked từ trước, KHÔNG ghi đè revoked_at để giữ audit trail",
  ], { fontSize: 11 }), {
    x: 0.5, y: 3.95, w: 9, h: 1.0,
    fontSize: 11, fontFace: FONT, color: C.text, paraSpaceAfter: 5, margin: 0,
  });
}

// ── 20. Revoke (B.7 + A.9) ───────────────────────────────────────────────────
{
  const s = newContentSlide("Revocation workflow · B.7 + A.9", "Customer yêu cầu · Admin duyệt · cert revoked", 20, TOTAL);

  // Swim lane
  const lanes = [
    { actor: "Customer", color: C.teal,    items: [
      "Vào \"Yêu cầu thu hồi\" (B.7)",
      "Chọn cert active của mình",
      "Nhập reason · Submit",
      "BOLA guard: cert WHERE owner_id=?",
    ]},
    { actor: "Admin",    color: C.navy,    items: [
      "Vào \"Duyệt thu hồi\" (A.9)",
      "Xem detail request + reason",
      "Approve / Reject (reason bắt buộc)",
      "Atomic: UPDATE request + UPDATE cert",
    ]},
  ];

  lanes.forEach((l, i) => {
    const y = 1.5 + i * 1.6;
    card(s, 0.5, y, 9, 1.4, { accent: l.color });
    pill(s, 0.7, y + 0.2, 1.2, 0.35, l.actor, C.white, l.color);
    s.addText(bullets(l.items, { fontSize: 11 }), {
      x: 2.1, y: y + 0.18, w: 7.2, h: 1.15,
      fontSize: 11, fontFace: FONT, color: C.text, paraSpaceAfter: 3, margin: 0,
    });
  });

  s.addText("Note: cert.revoked_at chỉ là DB state — chưa phản ánh ra ngoài cho tới khi Publish CRL (A.10).", {
    x: 0.5, y: 4.85, w: 9, h: 0.3,
    fontSize: 11, fontFace: FONT, italic: true, color: C.warning, align: "center", margin: 0,
  });
}

// ── 21. Publish CRL (A.10) ───────────────────────────────────────────────────
{
  const s = newContentSlide("Publish CRL · A.10", "Snapshot DB → ký → ghi file PEM · sync OCSP", 21, TOTAL);

  // Pipeline horizontal
  const steps = [
    { t: "Snapshot",   d: "SELECT serial, revoked_at\nFROM issued_certs\nWHERE revoked_at NOT NULL", c: C.teal },
    { t: "Build CRL",  d: "this_update = now\nnext_update = now+7d\nRevoked entries", c: C.navy },
    { t: "Sign",       d: "Root CA private key\nSHA-256 + RSA", c: C.midnight },
    { t: "Persist",    d: "certs/crl.pem\nINSERT crl_publications\nSync ocsp_db.json", c: C.success },
  ];
  steps.forEach((st, i) => {
    const x = 0.5 + i * 2.35, y = 1.55;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y, w: 2.15, h: 2.2, rectRadius: 0.1,
      fill: { color: st.c }, line: { type: "none" }, shadow: shadow(),
    });
    s.addText(st.t, {
      x, y: y + 0.15, w: 2.15, h: 0.4,
      fontSize: 14, fontFace: FONT, bold: true, color: C.white,
      align: "center", margin: 0,
    });
    s.addText(st.d, {
      x: x + 0.1, y: y + 0.65, w: 1.95, h: 1.4,
      fontSize: 9, fontFace: MONO, color: C.ice,
      align: "center", valign: "top", margin: 0,
    });
    if (i < steps.length - 1) {
      s.addShape(pres.shapes.LINE, {
        x: x + 2.15, y: y + 1.05, w: 0.2, h: 0,
        line: { color: C.text, width: 2, endArrowType: "triangle" },
      });
    }
  });

  s.addText(bullets([
    "CRL ký bởi Root CA → bất kỳ ai có Root CA cert đều verify được tính toàn vẹn của CRL",
    "OCSP responder dùng cùng dataset (ocsp_db.json) → trả realtime status cho từng serial",
    "crl.pem phát qua HTTP server (infra/crl_server, port 8889)",
  ], { fontSize: 11 }), {
    x: 0.5, y: 4.05, w: 9, h: 1.0,
    fontSize: 11, fontFace: FONT, color: C.text, paraSpaceAfter: 4, margin: 0,
  });
}

// ── 22. Verify 5 bước (B.9) ──────────────────────────────────────────────────
{
  const s = newContentSlide("Verify 5 bước · B.9", "Kiểm tra cert ngoài như browser thật làm", 22, TOTAL);

  const verifySteps = [
    { num: "1", t: "Signature",  d: "Verify cert sig bằng Root CA public key trong Trust Store" },
    { num: "2", t: "Validity",   d: "Now phải nằm trong [not_valid_before, not_valid_after]" },
    { num: "3", t: "Hostname",   d: "Hostname người dùng nhập khớp SAN / CN" },
    { num: "4", t: "CRL",        d: "Tải http://.../crl.pem · verify sig · check serial in revoked list" },
    { num: "5", t: "OCSP",       d: "Gọi http://.../ · trả good / revoked / unknown" },
  ];

  verifySteps.forEach((v, i) => {
    const y = 1.5 + i * 0.65;
    s.addShape(pres.shapes.OVAL, {
      x: 0.6, y, w: 0.55, h: 0.55,
      fill: { color: C.teal }, line: { type: "none" },
    });
    s.addText(v.num, {
      x: 0.6, y, w: 0.55, h: 0.55,
      fontSize: 18, fontFace: FONT, bold: true, color: C.white,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(v.t, {
      x: 1.4, y: y + 0.02, w: 2.2, h: 0.32,
      fontSize: 14, fontFace: FONT, bold: true, color: C.navy, margin: 0,
    });
    s.addText(v.d, {
      x: 3.7, y: y + 0.08, w: 5.9, h: 0.5,
      fontSize: 11, fontFace: FONT, color: C.text, margin: 0,
    });
    if (i < verifySteps.length - 1) {
      s.addShape(pres.shapes.LINE, {
        x: 0.87, y: y + 0.55, w: 0, h: 0.1,
        line: { color: C.muted, width: 1.2 },
      });
    }
  });

  s.addText("Bước 4 + 5 cần infra/crl_server + infra/ocsp_server đang chạy. App tự start ngầm khi launch GUI.", {
    x: 0.5, y: 4.85, w: 9, h: 0.3,
    fontSize: 10, fontFace: FONT, italic: true, color: C.muted, align: "center", margin: 0,
  });
}

// ── 23. Bảo mật C (encrypt-at-rest + scrypt + BOLA) ──────────────────────────
{
  const s = newContentSlide("Bảo mật cốt lõi · Lưu ý C", "Encrypt-at-rest · Hash password · Anti-BOLA", 23, TOTAL);

  const items = [
    {
      title: "AES-256-GCM encrypt-at-rest",
      pts: [
        "Master key 32 bytes trong master.key (gitignore)",
        "AAD bind theo row id → ngăn copy ciphertext",
        "Áp dụng cho root_ca + customer_keys.private_key",
      ],
      color: C.navy,
    },
    {
      title: "scrypt password hash",
      pts: [
        "N=16384, r=8, p=1 · salt 16 bytes random",
        "Format self-describing: scrypt$N$r$p$salt$hash",
        "Upgrade tham số sau vẫn verify được hash cũ",
      ],
      color: C.teal,
    },
    {
      title: "BOLA / IDOR guard",
      pts: [
        "Mọi customer query: WHERE owner_id = session.id",
        "Service layer chặn — không tin UI",
        "test_bola_guard: Bob không truy cập được key Alice",
      ],
      color: C.orange,
    },
  ];

  const cardW = 2.95, cardH = 3.55, gap = 0.13;
  items.forEach((it, i) => {
    const x = 0.5 + i * (cardW + gap);
    card(s, x, 1.45, cardW, cardH, { accent: it.color });
    s.addText(it.title, {
      x: x + 0.18, y: 1.6, w: cardW - 0.3, h: 0.6,
      fontSize: 13, fontFace: FONT, bold: true, color: it.color, margin: 0,
    });
    s.addText(bullets(it.pts, { fontSize: 11 }), {
      x: x + 0.18, y: 2.25, w: cardW - 0.3, h: 2.7,
      fontSize: 11, fontFace: FONT, color: C.text,
      paraSpaceAfter: 6, margin: 0,
    });
  });
}

// ── 24. Audit log (A.11) ─────────────────────────────────────────────────────
{
  const s = newContentSlide("Audit log · A.11", "Mọi hành động chính đều ghi nhận · filter theo action", 24, TOTAL);

  card(s, 0.5, 1.5, 9, 3.45, { accent: C.warning });

  // Header row
  const cols = ["timestamp", "actor", "action", "target", "details"];
  const widths = [1.5, 1.2, 2.4, 1.3, 2.4];
  let cx = 0.7;
  cols.forEach((c, i) => {
    s.addText(c.toUpperCase(), {
      x: cx, y: 1.65, w: widths[i], h: 0.3,
      fontSize: 9, fontFace: FONT, bold: true, color: C.muted,
      charSpacing: 3, margin: 0,
    });
    cx += widths[i];
  });
  s.addShape(pres.shapes.LINE, {
    x: 0.7, y: 1.95, w: 8.6, h: 0,
    line: { color: C.border, width: 0.5 },
  });

  const rows = [
    ["13:24:01", "admin",  "ROOT_CA_CREATED",      "root_ca:1", "CN=MHUD Demo Root CA"],
    ["13:26:08", "alice",  "REGISTER_SUCCESS",     "user:2",    "username=alice"],
    ["13:27:14", "alice",  "KEY_GENERATED",        "key:1",     "RSA 2048"],
    ["13:28:42", "alice",  "CSR_SUBMITTED",        "csr:1",     "CN=myshop.com"],
    ["13:30:17", "admin",  "CSR_APPROVED",         "csr:1",     "→ cert#1"],
    ["13:30:17", "admin",  "CERT_ISSUED",          "cert:1",    "serial=4A3F…"],
    ["13:42:55", "alice",  "REVOKE_REQUESTED",     "req:1",     "key compromised"],
    ["13:44:01", "admin",  "REVOKE_APPROVED",      "req:1",     "+ CERT_REVOKED"],
    ["13:45:30", "admin",  "CRL_PUBLISHED",        "crl:1",     "1 serial"],
  ];

  rows.forEach((r, i) => {
    const y = 2.05 + i * 0.30;
    cx = 0.7;
    r.forEach((cell, j) => {
      const isAction = j === 2;
      s.addText(cell, {
        x: cx, y, w: widths[j], h: 0.28,
        fontSize: 9, fontFace: isAction ? MONO : FONT,
        color: isAction ? C.navy : C.text,
        bold: isAction, margin: 0,
      });
      cx += widths[j];
    });
  });
}

// ── 25. Testing ──────────────────────────────────────────────────────────────
{
  const s = newContentSlide("Testing · 70 / 70 PASS", "8 module · BOLA + race + scenario integration", 25, TOTAL);

  // Big number left
  card(s, 0.5, 1.45, 3.0, 3.55, { accent: C.success });
  s.addText("70", {
    x: 0.5, y: 1.8, w: 3.0, h: 1.5,
    fontSize: 80, fontFace: FONT, bold: true, color: C.success,
    align: "center", margin: 0,
  });
  s.addText("test cases", {
    x: 0.5, y: 3.05, w: 3.0, h: 0.4,
    fontSize: 14, fontFace: FONT, color: C.muted,
    align: "center", margin: 0,
  });
  s.addText("100 % PASS", {
    x: 0.5, y: 3.55, w: 3.0, h: 0.5,
    fontSize: 16, fontFace: FONT, bold: true, color: C.success,
    align: "center", charSpacing: 3, margin: 0,
  });
  s.addText("8 module · Python unittest", {
    x: 0.5, y: 4.4, w: 3.0, h: 0.35,
    fontSize: 10, fontFace: FONT, color: C.muted,
    align: "center", italic: true, margin: 0,
  });

  // Right: module breakdown
  const mods = [
    { mod: "m1_foundation",     n: 8,  desc: "DB schema · master key" },
    { mod: "m4_ca_admin",       n: 10, desc: "Root CA · trust store" },
    { mod: "m5_customer",       n: 11, desc: "Register · keypair · BOLA" },
    { mod: "m6_csr_admin",      n: 9,  desc: "CSR submit · approve · race" },
    { mod: "m7_cert_lifecycle", n: 8,  desc: "Revoke · renew · expired" },
    { mod: "m8_revocation_crl", n: 9,  desc: "Workflow B.7 · publish CRL" },
    { mod: "m9_external_crl",   n: 7,  desc: "Upload · 5-step verify" },
    { mod: "scenarios",         n: 8,  desc: "End-to-end integration" },
  ];

  mods.forEach((m, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 3.7 + col * 2.95, y = 1.5 + row * 0.85;
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 2.85, h: 0.75,
      fill: { color: C.card },
      line: { color: C.border, width: 0.5 },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.04, h: 0.75,
      fill: { color: C.teal }, line: { type: "none" },
    });
    s.addText(m.mod, {
      x: x + 0.15, y: y + 0.08, w: 1.9, h: 0.3,
      fontSize: 10, fontFace: MONO, bold: true, color: C.navy, margin: 0,
    });
    s.addText(m.desc, {
      x: x + 0.15, y: y + 0.36, w: 1.9, h: 0.35,
      fontSize: 9, fontFace: FONT, color: C.muted, margin: 0,
    });
    s.addText(`${m.n}/${m.n}`, {
      x: x + 2.0, y: y + 0.2, w: 0.8, h: 0.4,
      fontSize: 14, fontFace: FONT, bold: true, color: C.success,
      align: "right", margin: 0,
    });
  });
}

// ── 26. Hạn chế + future ─────────────────────────────────────────────────────
{
  const s = newContentSlide("Hạn chế & hướng phát triển", "Trade-off đã chấp nhận · roadmap mở rộng", 26, TOTAL);

  card(s, 0.5, 1.45, 4.4, 3.55, { accent: C.warning });
  s.addText("⚠  Hạn chế hiện tại", {
    x: 0.7, y: 1.6, w: 4.0, h: 0.35,
    fontSize: 13, fontFace: FONT, bold: true, color: C.warning, margin: 0,
  });
  s.addText(bullets([
    { text: "Single Root CA — không hierarchy",  sub: "Rotate Root invalidate cert cũ" },
    { text: "Master key trên filesystem",        sub: "Không HSM · phụ thuộc file permission" },
    { text: "CRL kéo full mỗi lần verify",       sub: "Không Delta CRL · không OCSP stapling" },
    { text: "Desktop GUI duy nhất",              sub: "Không web · không REST API" },
    { text: "Username/password local",           sub: "Không SSO · không 2FA" },
  ], { fontSize: 11 }), {
    x: 0.7, y: 2.0, w: 4.0, h: 3.0,
    fontSize: 11, fontFace: FONT, color: C.text,
    paraSpaceAfter: 5, margin: 0,
  });

  card(s, 5.1, 1.45, 4.4, 3.55, { accent: C.teal });
  s.addText("✦  Hướng mở rộng", {
    x: 5.3, y: 1.6, w: 4.0, h: 0.35,
    fontSize: 13, fontFace: FONT, bold: true, color: C.teal, margin: 0,
  });
  s.addText(bullets([
    { text: "Intermediate CA hierarchy",     sub: "Root offline · Issuing CA online" },
    { text: "HSM PKCS#11 cho master key",    sub: "YubiHSM · Cloud KMS · SoftHSM" },
    { text: "ACME protocol (RFC 8555)",      sub: "Tự động cấp + renew cho web server" },
    { text: "OCSP stapling + Must-Staple",   sub: "Giảm tải OCSP responder" },
    { text: "REST API + 2FA TOTP",           sub: "Mở rộng ra web client" },
    { text: "Cert Transparency log mock",    sub: "Append-only · Merkle tree" },
  ], { fontSize: 11 }), {
    x: 5.3, y: 2.0, w: 4.0, h: 3.0,
    fontSize: 11, fontFace: FONT, color: C.text,
    paraSpaceAfter: 5, margin: 0,
  });
}

// ── 27. Closing ──────────────────────────────────────────────────────────────
{
  const s = pres.addSlide();
  addFuturisticBackdrop(s, 27, "hero");
  s.addImage({
    path: A.glassOrb,
    x: 7.25, y: 0.65, w: 2.05, h: 2.05,
    transparency: 12,
  });
  s.addImage({
    path: A.ring,
    x: -1.15, y: 2.20, w: 2.80, h: 4.20,
    transparency: 18,
  });

  s.addText("CẢM ƠN QUÝ THẦY CÔ", {
    x: 0.6, y: 0.55, w: 8.8, h: 0.45,
    fontSize: 12, fontFace: FONT, bold: true, color: C.orange,
    charSpacing: 10, align: "center", margin: 0,
  });

  s.addText("Hệ thống Quản lý & Cấp phát Chứng nhận X.509", {
    x: 0.85, y: 1.18, w: 8.3, h: 0.7,
    fontSize: 25, fontFace: FONT, bold: true, color: C.white,
    align: "center", margin: 0,
  });
  s.addText("HCMUS · FIT · Nhóm 7 · MHUD 2026", {
    x: 0.6, y: 1.92, w: 8.8, h: 0.4,
    fontSize: 12, fontFace: FONT, color: C.ice, italic: true,
    align: "center", charSpacing: 2, margin: 0,
  });

  // Recap row — centered
  const recap = [
    { k: "20 / 20", v: "yêu cầu chức năng" },
    { k: "70 / 70", v: "test cases PASS" },
    { k: "9",       v: "bảng DB + 5 layer" },
    { k: "AES-GCM", v: "encrypt-at-rest" },
  ];
  recap.forEach((it, i) => {
    const x = 0.55 + i * 2.275;
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: 2.62, w: 2.08, h: 0.92,
      fill: { color: C.card2, transparency: 7 },
      line: { color: i % 2 ? C.orange : C.teal, width: 0.65, transparency: 8 },
    });
    s.addText(it.k, {
      x, y: 2.77, w: 2.08, h: 0.38,
      fontSize: 21, fontFace: FONT, bold: true, color: i % 2 ? C.orange : C.teal,
      align: "center", margin: 0,
    });
    s.addText(it.v, {
      x: x + 0.08, y: 3.16, w: 1.92, h: 0.28,
      fontSize: 11, fontFace: FONT, color: C.ice,
      align: "center", margin: 0,
    });
  });

  s.addText("Q & A — sẵn sàng demo live", {
    x: 0.5, y: 4.16, w: 9, h: 0.45,
    fontSize: 20, fontFace: FONT, italic: true, bold: true, color: C.white,
    align: "center", charSpacing: 3, margin: 0,
  });
  s.addText("Video demo · 70 / 70 test pass · source GitHub trong báo cáo", {
    x: 0.5, y: 4.70, w: 9, h: 0.35,
    fontSize: 11, fontFace: FONT, color: C.ice,
    align: "center", margin: 0,
  });
  addFooter(s, 27, TOTAL);
}

// ── Write file ───────────────────────────────────────────────────────────────
pres.writeFile({ fileName: "docs/MHUD_X509_presentation.pptx" })
  .then(fn => console.log("✓ Built:", fn))
  .catch(err => { console.error("✗ Failed:", err); process.exit(1); });
