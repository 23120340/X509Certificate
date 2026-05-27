/*
 * Technical presentation deck for the X.509 Certificate Management project.
 *
 * Run:
 *   $env:NODE_PATH=(npm root -g); node docs/build_saas_pitch_deck.js
 *
 * Output:
 *   docs/MHUD_X509_presentation.pptx
 */

const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");

const pptx = new pptxgen();
pptx.defineLayout({ name: "LAYOUT_16x9", width: 10, height: 5.625 });
pptx.layout = "LAYOUT_16x9";
pptx.author = "Nhóm đồ án MHUD";
pptx.company = "HCMUS · FIT";
pptx.subject = "X.509 Certificate Management Technical Presentation";
pptx.title = "X.509 CA Management · Technical Deck";
pptx.lang = "vi-VN";
pptx.theme = {
  headFontFace: "Montserrat",
  bodyFontFace: "Montserrat",
  lang: "vi-VN",
};
pptx.margin = 0;

const FONT = "Montserrat";
const ASSET_DIR = path.join(__dirname, "assets", "futuristic");

const C = {
  ink: "101828",
  muted: "667085",
  blue: "2563EB",
  cyan: "38BDF8",
  purple: "7C3AED",
  pink: "EC4899",
  green: "10B981",
  orange: "F59E0B",
  red: "F43F5E",
  bg: "F7FAFF",
  white: "FFFFFF",
  line: "D9E2F2",
  dark: "0A1024",
  darkCard: "111827",
};

function asset(name) {
  const p = path.join(ASSET_DIR, name);
  return fs.existsSync(p) ? p : null;
}

function image(slide, name, opts) {
  const p = asset(name);
  if (p) slide.addImage({ path: p, ...opts });
}

function shadow() {
  return undefined;
}

function bg(slide, dark = false) {
  slide.background = { color: dark ? C.dark : C.bg };
  const glows = dark
    ? [
        [6.2, -1.2, 4.8, 3.0, C.purple, 70],
        [-1.0, 3.30, 3.5, 2.2, C.blue, 76],
        [7.0, 4.0, 2.8, 1.7, C.pink, 82],
      ]
    : [
        [6.6, -1.05, 4.4, 3.0, "DBEAFE", 34],
        [-1.0, 3.30, 3.3, 2.1, "E9D5FF", 36],
        [4.0, 4.65, 3.0, 1.2, "C7D2FE", 54],
      ];
  glows.forEach(([x, y, w, h, color, transparency]) => {
    slide.addShape(pptx.ShapeType.ellipse, {
      x, y, w, h,
      fill: { color, transparency },
      line: { color, transparency: 100 },
    });
  });
}

function header(slide, label, page, dark = false) {
  slide.addText("X509 CERTOPS", {
    x: 0.55, y: 0.28, w: 2.35, h: 0.22, margin: 0,
    fontFace: FONT, fontSize: 13, bold: true,
    color: dark ? C.white : C.blue,
  });
  slide.addText(label, {
    x: 6.45, y: 0.28, w: 2.30, h: 0.22, margin: 0,
    fontFace: FONT, fontSize: 13,
    color: dark ? "CBD5E1" : C.muted,
    align: "right",
  });
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 9.05, y: 0.20, w: 0.42, h: 0.34,
    rectRadius: 0.06,
    fill: { color: dark ? "1E293B" : C.white },
    line: { color: dark ? "334155" : C.line, width: 0.6 },
  });
  slide.addText(String(page).padStart(2, "0"), {
    x: 9.05, y: 0.27, w: 0.42, h: 0.16, margin: 0,
    fontFace: FONT, fontSize: 13, bold: true,
    color: dark ? C.white : C.ink,
    align: "center",
  });
}

function title(slide, text, sub, dark = false) {
  slide.addText(text, {
    x: 0.55, y: 0.82, w: 7.80, h: 0.62, margin: 0,
    fontFace: FONT, fontSize: 28, bold: true,
    color: dark ? C.white : C.ink,
  });
  if (sub) {
    slide.addText(sub, {
      x: 0.57, y: 1.54, w: 7.70, h: 0.45, margin: 0,
      fontFace: FONT, fontSize: 16,
      color: dark ? "CBD5E1" : C.muted,
      breakLine: false,
    });
  }
}

function card(slide, x, y, w, h, fill = C.white, dark = false) {
  slide.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h,
    rectRadius: 0.16,
    fill: { color: fill, transparency: dark ? 0 : 5 },
    line: { color: dark ? "334155" : "E4E7EC", width: 0.8 },
    shadow: shadow(dark ? 0.08 : 0.10, 11),
  });
}

function badge(slide, x, y, text, color = C.blue, dark = false, w = 0.62) {
  slide.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h: 0.44,
    rectRadius: 0.12,
    fill: { color: dark ? "172033" : "EEF2FF" },
    line: { color, width: 0.6 },
  });
  slide.addText(text, {
    x, y: y + 0.10, w, h: 0.18, margin: 0,
    fontFace: FONT, fontSize: 13, bold: true,
    color,
    align: "center",
  });
}

function pill(slide, x, y, w, text, color = C.blue, dark = false) {
  slide.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h: 0.42,
    rectRadius: 0.14,
    fill: { color: dark ? "172554" : C.white, transparency: dark ? 0 : 4 },
    line: { color, width: 0.8 },
  });
  slide.addText(text, {
    x, y: y + 0.11, w, h: 0.18, margin: 0,
    fontFace: FONT, fontSize: 13, bold: true,
    color: dark ? C.white : color,
    align: "center",
  });
}

function bulletList(slide, x, y, w, items, color = C.muted, size = 14, gap = 0.34) {
  items.forEach((item, i) => {
    slide.addText("• " + item, {
      x, y: y + i * gap, w, h: 0.34, margin: 0,
      fontFace: FONT, fontSize: size, color,
      breakLine: false,
    });
  });
}

function moduleCard(slide, x, y, w, h, label, heading, body, color, dark = false) {
  card(slide, x, y, w, h, dark ? C.darkCard : C.white, dark);
  if (h < 1.55) {
    slide.addText(`${label}  ${heading}`, {
      x: x + 0.18, y: y + 0.14, w: w - 0.36, h: 0.24, margin: 0,
      fontFace: FONT, fontSize: 13, bold: true,
      color: dark ? C.white : color,
      breakLine: false,
    });
    slide.addText(body, {
      x: x + 0.18, y: y + 0.44, w: w - 0.36, h: Math.max(0.18, h - 0.56), margin: 0,
      fontFace: FONT, fontSize: 13,
      color: dark ? "CBD5E1" : C.muted,
      breakLine: false,
    });
    return;
  }
  badge(slide, x + 0.22, y + 0.22, label, color, dark, 0.72);
  slide.addText(heading, {
    x: x + 0.24, y: y + 0.74, w: w - 0.48, h: 0.42, margin: 0,
    fontFace: FONT, fontSize: 15, bold: true,
    color: dark ? C.white : color,
  });
  slide.addText(body, {
    x: x + 0.24, y: y + 1.22, w: w - 0.48, h: Math.max(0.34, h - 1.36), margin: 0,
    fontFace: FONT, fontSize: 13,
    color: dark ? "CBD5E1" : C.muted,
    breakLine: false,
  });
}

function splitPanel(slide, x, y, w, h, label, heading, body, color, dark = false) {
  card(slide, x, y, w, h, dark ? C.darkCard : C.white, dark);
  slide.addShape(pptx.ShapeType.rect, {
    x, y, w: 0.14, h,
    fill: { color },
    line: { color, transparency: 100 },
  });
  if (h < 1.10) {
    slide.addText(`${label}  ${heading}`, {
      x: x + 0.34, y: y + 0.13, w: w - 0.62, h: 0.24, margin: 0,
      fontFace: FONT, fontSize: 13, bold: true,
      color: dark ? C.white : color,
      breakLine: false,
    });
    slide.addText(body, {
      x: x + 0.34, y: y + 0.42, w: w - 0.62, h: Math.max(0.20, h - 0.54), margin: 0,
      fontFace: FONT, fontSize: 13,
      color: dark ? "CBD5E1" : C.muted,
      breakLine: false,
    });
    return;
  }
  slide.addText(label, {
    x: x + 0.34, y: y + 0.28, w: 0.78, h: 0.28, margin: 0,
    fontFace: FONT, fontSize: 13, bold: true,
    color,
  });
  slide.addText(heading, {
    x: x + 1.12, y: y + 0.26, w: w - 1.42, h: 0.36, margin: 0,
    fontFace: FONT, fontSize: 16, bold: true,
    color: dark ? C.white : C.ink,
  });
  slide.addText(body, {
    x: x + 0.34, y: y + 0.84, w: w - 0.66, h: h - 1.02, margin: 0,
    fontFace: FONT, fontSize: 13,
    color: dark ? "CBD5E1" : C.muted,
    breakLine: false,
  });
}

function stepCard(slide, x, y, w, n, heading, bullets, color = C.blue) {
  card(slide, x, y, w, 2.45, n === "3" || n === "6" ? "F5F3FF" : C.white);
  slide.addShape(pptx.ShapeType.ellipse, {
    x: x + 0.22, y: y + 0.28, w: 0.44, h: 0.44,
    fill: { color },
    line: { color, transparency: 100 },
  });
  slide.addText(n, {
    x: x + 0.22, y: y + 0.39, w: 0.44, h: 0.18, margin: 0,
    fontFace: FONT, fontSize: 15, bold: true,
    color: C.white,
    align: "center",
  });
  slide.addText(heading, {
    x: x + 0.82, y: y + 0.28, w: w - 1.05, h: 0.48, margin: 0,
    fontFace: FONT, fontSize: 17, bold: true,
    color: C.ink,
    breakLine: false,
  });
  bulletList(slide, x + 0.32, y + 1.04, w - 0.62, bullets, C.muted, 14, 0.50);
}

function addCover() {
  const s = pptx.addSlide();
  bg(s, true);
  header(s, "MHUD 2026", 1, true);
  image(s, "primary_ring.png", { x: 6.74, y: 0.54, w: 2.44, h: 2.44 });
  image(s, "glass_torus.png", { x: 5.28, y: 3.32, w: 1.42, h: 1.42 });
  pill(s, 0.58, 0.88, 2.20, "LOCAL-FIRST CA OPS", C.blue, true);
  s.addText("X509 CertOps", {
    x: 0.55, y: 1.44, w: 4.80, h: 0.55, margin: 0,
    fontFace: FONT, fontSize: 34, bold: true, color: C.white,
  });
  s.addText("Từ lý thuyết certificate đến hệ thống quản lý CA có lifecycle và audit trail.", {
    x: 0.58, y: 2.18, w: 4.70, h: 0.52, margin: 0,
    fontFace: FONT, fontSize: 16, color: "CBD5E1",
  });
  pill(s, 0.58, 3.02, 1.62, "Mục tiêu", C.blue, true);
  pill(s, 2.42, 3.02, 2.58, "Root CA · CSR · CRL · OCSP", C.cyan, true);
  [["Python", "core"], ["AES-GCM", "key at-rest"], ["5-step", "verify"]].forEach((m, i) => {
    const x = 0.70 + i * 1.42;
    slideMetric(s, x, 4.05, m[0], m[1], i === 1 ? C.pink : C.cyan, true);
  });
  moduleCard(s, 5.68, 1.42, 3.70, 2.82, "CA", "Certificate Operations", "Root CA, CSR Queue, Certificate Lifecycle, Audit Log.", C.cyan, true);
  return s;
}

function slideMetric(slide, x, y, value, label, color, dark = false) {
  slide.addText(value, {
    x, y, w: 1.24, h: 0.26, margin: 0,
    fontFace: FONT, fontSize: 18, bold: true,
    color,
    align: "center",
  });
  slide.addText(label, {
    x, y: y + 0.34, w: 1.24, h: 0.20, margin: 0,
    fontFace: FONT, fontSize: 13,
    color: dark ? "CBD5E1" : C.muted,
    align: "center",
  });
}

function addProblem() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "Problem", 2);
  title(s, "Vấn đề cần giải quyết", "Quản lý certificate thủ công làm phân tán dữ liệu cấp phát, trạng thái tin cậy và lịch sử thao tác.");
  const items = [
    ["DB", "Dữ liệu phân tán", "Cert, CSR, serial, expiry và revoke status nằm rải rác trong nhiều file.", C.blue],
    ["CA", "Nguồn tin cậy", "Ghép Root CA, Trust Store, CRL/OCSP; sai một bước là verify fail.", C.red],
    ["LOG", "Key & audit rủi ro", "Private key dễ lưu file phẳng; thiếu log ai tạo, duyệt, thu hồi certificate.", C.purple],
  ];
  items.forEach((it, i) => moduleCard(s, 0.62 + i * 3.05, 2.06, 2.70, 1.88, it[0], it[1], it[2], it[3]));
  card(s, 0.70, 4.25, 8.55, 0.58, "F8FBFF");
  badge(s, 0.96, 4.32, "!", C.purple, false, 0.48);
  s.addText("Hệ quả: cert hết hạn hoặc đã revoke vẫn được dùng; khi sự cố xảy ra rất khó truy vết nguyên nhân.", {
    x: 1.62, y: 4.40, w: 7.18, h: 0.20, margin: 0,
    fontFace: FONT, fontSize: 14, bold: true, color: C.ink,
  });
  return s;
}

function addX509Overview() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "X.509 Overview", 3);
  title(s, "X.509 là gì?", "Không phải phần mềm; X.509 là chuẩn dữ liệu mô tả certificate số.");
  card(s, 0.68, 2.02, 4.08, 2.28, "FFFFFF");
  badge(s, 0.98, 2.28, "CRT", C.blue, false, 0.70);
  s.addText("Identity + Public Key", {
    x: 0.98, y: 2.95, w: 3.40, h: 0.34, margin: 0,
    fontFace: FONT, fontSize: 22, bold: true, color: C.ink,
  });
  s.addText("Certificate ràng buộc danh tính thật như domain, tổ chức hoặc thiết bị với public key của chủ thể đó.", {
    x: 1.00, y: 3.46, w: 3.22, h: 0.54, margin: 0,
    fontFace: FONT, fontSize: 13, color: C.muted,
  });
  const binds = [
    ["Subject", "Ai sở hữu cert", C.blue],
    ["Public Key", "Khóa được công bố", C.purple],
    ["CA Signature", "Bằng chứng không bị sửa", C.pink],
  ];
  binds.forEach((b, i) => splitPanel(s, 5.16, 2.02 + i * 0.78, 3.98, 0.58, `0${i + 1}`, b[0], b[1], b[2]));
  card(s, 0.86, 4.62, 8.02, 0.44, "F8FBFF");
  slideTextCenter(s, 1.08, 4.75, 7.58, "Trong đồ án: X.509 là lõi cho cấp cert, thu hồi, publish CRL và client verify.", 13, C.ink, true);
  return s;
}

function addCertAnatomy() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "Certificate Anatomy", 4);
  title(s, "Cấu trúc X.509 certificate", "Phần TBS chứa dữ liệu cần ký; CA ký lên TBS để chống giả mạo.");
  card(s, 0.66, 2.00, 3.02, 2.70, "FFFFFF");
  s.addText("TBSCertificate", {
    x: 0.92, y: 2.30, w: 2.34, h: 0.32, margin: 0,
    fontFace: FONT, fontSize: 19, bold: true, color: C.blue,
    align: "center",
  });
  bulletList(s, 0.94, 2.90, 2.30, ["Subject / Issuer", "Serial / Validity", "Subject Public Key", "Extensions v3"], C.muted, 13, 0.36);
  card(s, 4.02, 2.00, 2.10, 2.70, "F5F3FF");
  s.addText("Signature Algorithm", { x: 4.28, y: 2.44, w: 1.58, h: 0.50, margin: 0, fontFace: FONT, fontSize: 17, bold: true, color: C.purple, align: "center" });
  s.addText("sha256WithRSAEncryption", { x: 4.26, y: 3.30, w: 1.62, h: 0.34, margin: 0, fontFace: FONT, fontSize: 13, color: C.muted, align: "center" });
  card(s, 6.46, 2.00, 2.88, 2.70, "FFFFFF");
  s.addText("Signature Value", {
    x: 6.78, y: 2.42, w: 2.24, h: 0.34, margin: 0,
    fontFace: FONT, fontSize: 19, bold: true, color: C.pink,
    align: "center",
  });
  s.addText("CA dùng private key ký hash của TBS. Client dùng public key CA để kiểm tra lại.", {
    x: 6.86, y: 3.08, w: 2.06, h: 0.76, margin: 0,
    fontFace: FONT, fontSize: 13, color: C.muted,
    align: "center",
  });
  card(s, 0.86, 4.92, 8.02, 0.34, "F8FBFF");
  slideTextCenter(s, 1.12, 5.01, 7.50, "Serial dùng để truy vết và revoke; Validity kiểm tra thời hạn; Extensions quyết định cách cert được dùng.", 13, C.ink, true);
  return s;
}

function addX509V3Extensions() {
  const s = pptx.addSlide();
  bg(s, true);
  header(s, "X.509 v3 Extensions", 5, true);
  title(s, "Material quan trọng của X.509 v3", "v3 thêm extensions để certificate mô tả rõ phạm vi sử dụng, tên miền và nơi kiểm tra thu hồi.", true);
  image(s, "glass_orb.png", { x: 7.68, y: 0.82, w: 1.15, h: 1.15 });
  const ext = [
    ["SAN", "Subject Alt Name", "DNS/IP/email được cert bảo vệ; TLS hiện đại dựa vào SAN.", C.cyan],
    ["KU", "Key Usage", "Giới hạn khóa: digitalSignature, keyEncipherment hoặc ký CRL.", C.purple],
    ["EKU", "Extended Usage", "Phân biệt serverAuth, clientAuth, code signing hoặc email.", C.pink],
    ["BC", "Basic Constraints", "Phân biệt Root CA với end-entity certificate trong đồ án.", C.green],
    ["CRL", "CRLDP", "Địa chỉ để client tải CRL và kiểm tra serial đã thu hồi.", C.cyan],
    ["AIA", "AIA / OCSP", "Chỉ ra OCSP hoặc CA issuer endpoint nếu hệ thống hỗ trợ.", C.orange],
  ];
  ext.forEach((e, i) => moduleCard(s, 0.58 + (i % 3) * 3.06, 2.06 + Math.floor(i / 3) * 1.44, 2.76, 1.12, e[0], e[1], e[2], e[3], true));
  return s;
}

function addTrustModel() {
  const s = pptx.addSlide();
  bg(s, true);
  header(s, "Client Verify Model", 6, true);
  title(s, "Root CA → Trust Store → Client Verify", "Client lấy public key tin cậy từ Trust Store để kiểm tra certificate do Root CA ký.", true);
  image(s, "glass_orb.png", { x: 7.75, y: 0.92, w: 1.10, h: 1.10 });
  const nodes = [
    ["Root CA", "Self-signed CA; private key dùng để ký server cert và CRL.", C.cyan],
    ["Trust Store", "Lưu root_ca.crt; client lấy public key tin cậy từ đây.", C.purple],
    ["Client Verify", "Kiểm tra signature, validity, hostname, CRL và OCSP.", C.pink],
  ];
  nodes.forEach((n, i) => {
    const x = 0.70 + i * 3.05;
    moduleCard(s, x, 2.35, 2.55, 1.45, "CA", n[0], n[1], n[2], true);
    if (i < 2) s.addShape(pptx.ShapeType.line, { x: x + 2.55, y: 3.05, w: 0.50, h: 0.01, line: { color: n[2], width: 1.4 } });
  });
  card(s, 0.88, 4.42, 8.02, 0.48, "172033", true);
  s.addText("Repo: core/ca.py publish Root CA; core/verify.py tìm Root CA trong Trust Store để verify server cert.", {
    x: 1.10, y: 4.55, w: 7.58, h: 0.16, margin: 0,
    fontFace: FONT, fontSize: 13, bold: true, color: "E0F2FE", align: "center",
  });
  return s;
}

function addSolution() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "Giải pháp", 7);
  title(s, "Giải pháp triển khai", "Trong đồ án: quản lý vòng đời chứng chỉ, publish CRL và client verify.");
  const items = [
    ["01", "Customer", "Tạo keypair và submit CSR chuẩn PKCS#10."],
    ["02", "Admin", "Duyệt CSR, Root CA ký certificate."],
    ["03", "Client", "Verify Root CA trust, hostname, CRL và OCSP."],
  ];
  items.forEach((it, i) => moduleCard(s, 0.78, 2.02 + i * 0.92, 4.35, 0.74, it[0], it[1], it[2], i === 1 ? C.purple : C.blue));
  moduleCard(s, 5.82, 2.02, 3.35, 2.58, "SYS", "Các trạng thái chính", "pending CSR → approved → issued cert → revoked → CRL published.", C.green);
  pill(s, 0.80, 4.68, 2.20, "APP LOCAL · DEMO OFFLINE", C.blue);
  return s;
}

function addFeatures() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "System Modules", 8);
  title(s, "Chức năng chính hệ thống CA", "Mỗi chức năng tương ứng một module trong kiến trúc đồ án.");
  const feats = [
    ["CA", "CA Admin", "Sinh Root CA và publish trust store.", C.blue],
    ["CSR", "CSR Queue", "Duyệt CSR có proof-of-possession.", C.purple],
    ["KEY", "Key Vault", "AES-256-GCM bảo vệ private key.", C.green],
    ["API", "CRL/OCSP", "Publish CRL và sync trạng thái revoke.", C.cyan],
    ["KPI", "5-Step Verify", "Signature, validity, hostname, CRL, OCSP.", C.blue],
    ["LOG", "Audit Log", "Theo dõi actor, action, target, details.", C.pink],
  ];
  feats.forEach((f, i) => moduleCard(s, 0.58 + (i % 3) * 3.06, 2.02 + Math.floor(i / 3) * 1.48, 2.76, 1.18, f[0], f[1], f[2], f[3]));
  return s;
}

function addUserFlow() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "User Flow", 9);
  title(s, "Từ CSR đến certificate được verify", "Luồng demo thể hiện đúng lifecycle của một certificate trong hệ thống.");
  const flow = [
    ["1", "Generate Key"], ["2", "Submit CSR"], ["3", "Approve"],
    ["4", "Issue Cert"], ["5", "Publish"], ["6", "Verify"],
  ];
  flow.forEach((f, i) => {
    const x = 0.55 + i * 1.50;
    card(s, x, 2.38, 1.18, 1.25, i === 3 ? "F5F3FF" : C.white);
    badge(s, x + 0.34, 2.60, f[0], i === 3 ? C.purple : C.blue, false, 0.50);
    slideTextCenter(s, x + 0.12, 3.12, 0.94, f[1], 13, C.ink, true);
    if (i < flow.length - 1) s.addShape(pptx.ShapeType.line, { x: x + 1.18, y: 2.98, w: 0.32, h: 0.01, line: { color: "9DB5FF", width: 1.1 } });
  });
  card(s, 0.70, 4.35, 8.58, 0.48, "F8FBFF");
  slideTextCenter(s, 0.96, 4.48, 8.06, "CSR chứng minh customer sở hữu private key; admin chỉ duyệt và ký cert.", 13, C.ink, true);
  return s;
}

function slideTextCenter(slide, x, y, w, text, fontSize, color, bold = false) {
  slide.addText(text, { x, y, w, h: 0.18, margin: 0, fontFace: FONT, fontSize, bold, color, align: "center" });
}

function addArchitecture() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "System Architecture", 10);
  title(s, "Kiến trúc hệ thống", "Tách UI, service layer, crypto core và storage để mỗi phần có trách nhiệm rõ ràng.");
  const layers = [
    ["UI", "Presentation", "Tkinter/ttk UI cho Admin và Customer; nhận input và gọi service.", C.blue],
    ["API", "Service Layer", "Kiểm tra quyền, xử lý workflow CSR/revoke và ghi audit log.", C.purple],
    ["ENC", "Crypto Core", "Tách logic RSA, X.509, CSR, CRL, verify và AES-GCM.", C.green],
    ["DB", "Storage / Infra", "SQLite, Trust Store, PEM, CRL server và OCSP DB cho demo.", C.cyan],
  ];
  layers.forEach((l, i) => moduleCard(s, 0.72 + (i % 2) * 4.46, 2.02 + Math.floor(i / 2) * 1.42, 4.05, 1.16, l[0], l[1], l[2], l[3]));
  return s;
}

function addServiceDataFlow() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "Service / Data Flow", 11);
  title(s, "Luồng xử lý chính", "Mỗi thao tác đi qua service layer trước khi chạm vào crypto core hoặc database.");
  stepCard(s, 0.62, 2.08, 2.76, "1", "Customer tạo CSR", ["Sinh RSA keypair", "Tạo CSR PKCS#10", "Ký CSR bằng private key"], C.blue);
  stepCard(s, 3.62, 2.08, 2.76, "2", "Admin duyệt CSR", ["Kiểm tra owner", "Verify chữ ký CSR", "Đổi trạng thái approved"], C.blue);
  stepCard(s, 6.62, 2.08, 2.76, "3", "Root CA ký cert", ["Ký certificate", "Gắn serial, validity", "Thêm KU/EKU, SAN, CRLDP/AIA"], C.purple);
  return s;
}

function addVerifyDataFlow() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "State / Verify Flow", 12);
  title(s, "Lưu trạng thái, publish CRL và verify", "Sau khi phát hành, hệ thống theo dõi vòng đời certificate và cho client kiểm chứng trạng thái.");
  stepCard(s, 0.62, 2.08, 2.76, "4", "Lưu DB và audit", ["issued_certs lưu serial/status", "audit_log ghi actor"], C.blue);
  stepCard(s, 3.62, 2.08, 2.76, "5", "Thu hồi và publish", ["Admin approve revoke", "crl_publish tạo CRL"], C.blue);
  stepCard(s, 6.62, 2.08, 2.76, "6", "Client verify", ["Verify cert bằng Root CA", "Check validity, SAN, CRL/OCSP"], C.purple);
  return s;
}

function addTechStack() {
  const s = pptx.addSlide();
  bg(s);
  header(s, "Implementation Stack", 13);
  title(s, "Ngôn ngữ & stack triển khai", "Python làm lõi, Tkinter/ttk cho UI desktop và SQLite để lưu trạng thái demo.");
  const stacks = [
    ["</>", "Python", "main.py, service layer và core crypto; phần lớn dùng module có sẵn.", C.blue],
    ["UI", "Tkinter / ttk", "UI cho Admin và Customer: tạo key, submit CSR, duyệt, revoke.", C.purple],
    ["DB", "SQLite", "Lưu users, root_ca, customer_keys, CSR, issued cert, revoke request, audit.", C.cyan],
    ["API", "Lab infra", "HTTP CRL/OCSP server; legacy socket GET_CERT cho verification lab.", C.orange],
  ];
  stacks.forEach((st, i) => moduleCard(s, 0.72 + (i % 2) * 4.46, 2.02 + Math.floor(i / 2) * 1.42, 4.02, 1.16, st[0], st[1], st[2], st[3]));
  card(s, 0.72, 4.78, 8.56, 0.44, "F8FBFF");
  slideTextCenter(s, 0.95, 4.92, 8.10, "requirements.txt: cryptography>=41.0.0; các phần còn lại chủ yếu là module Python có sẵn.", 13, C.ink, true);
  return s;
}

function addCrlRevocationMaterial() {
  const s = pptx.addSlide();
  bg(s, true);
  header(s, "CRL / Revocation", 14, true);
  title(s, "Material thu hồi chứng chỉ", "CRL giúp client biết certificate đã bị vô hiệu hóa trước khi hết hạn.", true);
  const items = [
    ["ALG", "Signature Algorithm", "Thuật toán CA dùng để ký danh sách thu hồi.", C.cyan],
    ["ISS", "Issuer Name", "Root CA phát hành CRL để client kiểm tra nguồn gốc.", C.purple],
    ["TIME", "This / Next Update", "Mốc tạo CRL và thời điểm cần publish bản mới.", C.pink],
    ["LIST", "Revoked Certificates", "CRL lưu serial và ngày thu hồi; reason nằm ở DB/UI.", C.green],
  ];
  items.forEach((it, i) => splitPanel(s, 0.74 + (i % 2) * 4.38, 2.12 + Math.floor(i / 2) * 1.26, 3.92, 1.00, it[0], it[1], it[2], it[3], true));
  card(s, 0.84, 4.86, 8.18, 0.42, "172033", true);
  slideTextCenter(s, 1.10, 4.99, 7.66, "Trong đồ án: admin approve revoke → publish CRL → client tải CRL và so serial khi verify.", 13, "E0F2FE", true);
  return s;
}

function addCodeHighlights() {
  const s = pptx.addSlide();
  bg(s, true);
  header(s, "Code Highlights", 15, true);
  title(s, "Các đoạn code lõi", "Tập trung vào hai luồng quan trọng nhất: phát hành certificate và client verify.", true);
  moduleCard(s, 0.72, 2.05, 4.15, 1.75, "</>", "src/core/cert_builder.py", "Đặt subject, issuer, extensions rồi ký bằng Root CA private key.", C.cyan, true);
  moduleCard(s, 5.10, 2.05, 4.15, 1.75, "</>", "src/core/verify.py", "Tìm Root CA trong Trust Store, verify chữ ký rồi check validity/SAN/CRL/OCSP.", C.purple, true);
  moduleCard(s, 0.72, 3.98, 4.15, 0.98, "CSR", "csr.py", "Tạo PKCS#10 request và verify proof-of-possession.", C.cyan, true);
  moduleCard(s, 5.10, 3.98, 4.15, 0.98, "KEY", "encryption.py", "AES-256-GCM bảo vệ private key; scrypt hash password.", C.green, true);
  return s;
}

function addRoadmapFinal() {
  const s = pptx.addSlide();
  bg(s, true);
  header(s, "Kết luận", 16, true);
  image(s, "glass_loops.png", { x: 7.16, y: 0.72, w: 1.88, h: 1.88 });
  pill(s, 0.62, 0.92, 1.86, "TỔNG KẾT ĐỒ ÁN", C.blue, true);
  s.addText("Hoàn thiện mô hình CA nội bộ", {
    x: 0.62, y: 1.46, w: 5.80, h: 0.70, margin: 0,
    fontFace: FONT, fontSize: 30, bold: true, color: C.white,
  });
  s.addText("Đồ án triển khai đầy đủ luồng Root CA, CSR, phát hành certificate, thu hồi, publish CRL và client verify.", {
    x: 0.64, y: 2.58, w: 5.30, h: 0.45, margin: 0,
    fontFace: FONT, fontSize: 15, color: "CBD5E1",
  });
  const phases = [
    ["Hiện tại", "MVP đồ án", "Root CA · CSR · CRL · Audit"],
    ["Mở rộng", "Tăng độ tin cậy", "Policy · RBAC · Backup"],
    ["Nâng cao", "Triển khai an toàn", "Web UI · API · HSM/KMS"],
  ];
  phases.forEach((p, i) => {
    const x = 0.70 + i * 3.02;
    moduleCard(s, x, 3.70, 2.54, 1.02, "→", p[0], `${p[1]}\n${p[2]}`, i === 2 ? C.green : i === 1 ? C.purple : C.cyan, true);
  });
  moduleCard(s, 6.38, 2.34, 2.78, 0.72, "Q", "Q&A", "Demo quy trình verify.", C.cyan, true);
  return s;
}

const slideFns = [
  addCover,
  addProblem,
  addX509Overview,
  addCertAnatomy,
  addX509V3Extensions,
  addTrustModel,
  addSolution,
  addFeatures,
  addUserFlow,
  addArchitecture,
  addServiceDataFlow,
  addVerifyDataFlow,
  addTechStack,
  addCrlRevocationMaterial,
  addCodeHighlights,
  addRoadmapFinal,
];

const selectedSlides = (process.env.SLIDES || "")
  .split(",")
  .map((n) => Number(n.trim()))
  .filter((n) => Number.isInteger(n) && n >= 1 && n <= slideFns.length);
const activeSlideFns = selectedSlides.length
  ? selectedSlides.map((n) => slideFns[n - 1])
  : slideFns;

activeSlideFns.forEach((fn) => fn());

const outFile = process.env.OUT || "docs/MHUD_X509_presentation.pptx";
pptx.writeFile({ fileName: outFile })
  .then((fn) => console.log("Built technical deck:", fn))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
