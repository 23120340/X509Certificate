# Demo Script — Hệ thống Quản lý CA X.509

Kịch bản demo cho video YouTube (unlisted) — đáp ứng yêu cầu nộp đồ án MHUD.

> **Thời lượng dự kiến**: 12–15 phút. Có thể cắt thành 2 phần nếu dài hơn 10 phút.

---

## Chuẩn bị trước khi quay

1. **Xoá state cũ** (để chứng minh first-run flow):
   ```powershell
   Remove-Item d:\repos\X509Certificate\ca_app.db, d:\repos\X509Certificate\master.key -ErrorAction SilentlyContinue
   Remove-Item d:\repos\X509Certificate\certs -Recurse -Force -ErrorAction SilentlyContinue
   ```

2. **Mở 2 cửa sổ**:
   - Terminal: `cd d:\repos\X509Certificate; python main.py`
   - VS Code mở repository để show source code khi cần

3. **Chuẩn bị thoại** cho 3 nhân vật:
   - **Admin** — `admin` / `Admin@123` (mặc định first-run)
   - **Customer Alice** — sẽ đăng ký trong demo
   - **Customer Bob** — sẽ đăng ký để minh hoạ BOLA guard

4. **Verification Lab**: chuẩn bị cert/key dummy sẵn để upload thử (export 1 cert ra file trước khi quay).

---

## Cấu trúc video

```
00:00–00:30   Intro + mô hình tin cậy
00:30–02:30   Phần 1 — Admin first-run + cấu hình hệ thống + sinh Root CA
02:30–04:30   Phần 2 — Customer đăng ký + sinh keypair + submit CSR
04:30–06:30   Phần 3 — Admin duyệt CSR + phát hành cert
06:30–08:00   Phần 4 — Customer download cert + cert detail
08:00–10:30   Phần 5 — Revocation workflow + Publish CRL
10:30–12:30   Phần 6 — Tra cứu CRL + Upload cert ngoài + 5-bước verify
12:30–14:00   Phần 7 — Bảo mật (encrypt-at-rest, BOLA, audit log)
14:00–15:00   Closing — recap + 70/70 tests
```

---

## Phần 0 — Intro (00:00–00:30)

**Hình**: README screenshot + diagram mô hình tin cậy.

**Thoại**:
> "Đồ án Mã hoá & Ứng dụng — Hệ thống Quản lý và Cấp phát Chứng nhận X.509 cho dịch vụ Website.
>
> Hệ thống gồm 2 nhóm người dùng:
> - **Admin** — quản trị Root CA, duyệt CSR, quản lý lifecycle cert, publish CRL.
> - **Customer** — sinh keypair, xin cấp cert cho domain, theo dõi + thu hồi cert của mình.
>
> Tech stack: Python 3.14 + Tkinter + SQLite + cryptography (RSA/PKCS10/X.509). Dữ liệu nhạy cảm — private key — được mã hoá AES-256-GCM trước khi lưu DB."

---

## Phần 1 — Admin First-run + Root CA (00:30–02:30)

### 1.1 Bootstrap

**Action**: Chạy `python main.py`.

**Hình**:
- Terminal in: `[bootstrap] Default admin created: username='admin', password='Admin@123'. CHANGE IT after first login.`
- GUI hiện màn hình Login.

**Thoại**:
> "Lần đầu chạy, hệ thống tự init SQLite database `ca_app.db`, sinh master key 32 bytes ngẫu nhiên trong file `master.key` (cho AES-GCM), seed cấu hình mặc định và tạo tài khoản admin first-run."

### 1.2 Login admin + đổi mật khẩu (A.1 + A.2)

**Action**: Login `admin/Admin@123` → bấm nút "Đổi mật khẩu" → đổi sang `AdminSecure#2026`.

**Thoại**:
> "A.1 Đăng nhập, A.2 đổi mật khẩu. Mật khẩu được hash bằng `scrypt` — tham số N=16384, r=8, p=1, salt 16-byte ngẫu nhiên. Hash format self-describing `scrypt$N$r$p$salt$hash` để upgrade tham số sau này vẫn verify được hash cũ."

### 1.3 Cấu hình hệ thống (A.3)

**Action**: Menu sidebar → "Cấu hình hệ thống (A.3)" → đổi `default_key_size` từ 2048 sang 3072 → Lưu.

**Hình**: Status "Đã lưu 1 thay đổi." màu xanh.

**Thoại**:
> "A.3 — cấu hình tham số cấp phát. Form whitelist 5 key, mỗi key validate đúng kiểu (int / enum). Mỗi thay đổi ghi vào audit log."

### 1.4 Sinh Root CA (A.4 + A.5)

**Action**: Menu → "Root CA (A.4-5)" → bấm "🔑 Sinh Root CA" → nhập CN `MHUD Demo Root CA` → key size 2048 → validity 3650 → bấm Sinh.

**Hình**: Hộp thoại thành công + bảng active CA hiển thị.

**Thoại**:
> "A.4 sinh keypair Root CA + A.5 phát hành Root Certificate. Private key của Root CA được mã hoá AES-256-GCM với AAD=`root_ca` trước khi lưu vào bảng `root_ca`. Master key trong file `master.key` không bao giờ được hardcode hay commit vào git.
>
> Tôi sẽ chứng minh điều này lát nữa khi xem DB."

### 1.5 Publish ra Trust Store

**Action**: Bấm "📁 Publish ra Trust Store".

**Thoại**:
> "Ghi cert PEM của Root CA ra `certs/trust_store/root_ca.crt` để client (và infra/crl_server, ocsp_server) load khi cần verify."

---

## Phần 2 — Customer onboarding (02:30–04:30)

### 2.1 Đăng xuất + đăng ký Alice (B.1 + B.2)

**Action**: Đăng xuất → tab "Đăng ký (Customer)" → username `alice` / password `AlicePw#2026` / xác nhận → tự động login.

**Thoại**:
> "B.1 đăng ký customer + B.2 đăng nhập. Customer tự đăng ký được, Admin chỉ do hệ thống seed. Sau register tự login luôn để UX mượt."

### 2.2 Sinh keypair RSA (B.4)

**Action**: Sidebar → "Keypair của tôi (B.4)" → "🔑 Sinh keypair mới" → name `main-key` → key size 2048 → bấm Sinh.

**Hình**: Bảng list keypair hiện 1 row.

**Thoại**:
> "B.4 sinh keypair RSA-2048 cho khách hàng. Private key được mã hoá AES-GCM với AAD=`customer_keys:{id}` — AAD bind theo id row, copy ciphertext sang row khác không decrypt được. Public key lưu plain để ai cũng đọc."

### 2.3 Xem public key

**Action**: Chọn keypair → "📋 Xem public key" → modal hiển thị PEM.

**Thoại**:
> "Public key xuất ra PEM chuẩn `SubjectPublicKeyInfo`."

### 2.4 Submit CSR (B.5)

**Action**: Sidebar → "Yêu cầu cấp cert (B.5-6)" → chọn keypair `main-key` → CN `myshop.com` → SAN `www.myshop.com, api.myshop.com` → Submit.

**Hình**: Bảng CSR hiện 1 row với status `pending` (màu cam).

**Thoại**:
> "B.5 tạo CSR theo PKCS#10. CSR ký bằng private key của customer → admin có thể verify proof-of-possession trước khi phát hành. CN tự thêm vào SAN nếu user quên (chuẩn TLS hiện đại)."

---

## Phần 3 — Admin duyệt CSR + phát hành cert (04:30–06:30)

### 3.1 Đăng xuất + login admin

**Action**: Đăng xuất Alice → login `admin/AdminSecure#2026`.

### 3.2 Xem queue CSR (A.6 + A.7)

**Action**: Sidebar → "Duyệt CSR (A.6-7)" → filter mặc định "pending" → bảng hiện CSR của Alice.

**Thoại**:
> "A.6 / A.7 — queue CSR. Bảng JOIN với users để hiện username của requester, status có màu (pending = cam)."

### 3.3 Xem chi tiết CSR

**Action**: Chọn CSR → "📋 Xem chi tiết" → modal hiển thị CSR PEM + thông tin.

### 3.4 Approve CSR

**Action**: Bấm "✅ Approve" → nhập validity 365 → bấm "Phát hành".

**Hình**: Hộp thoại "Đã phát hành — Cert #1 (serial ...) hết hạn ..."

**Thoại**:
> "Approve trigger pipeline:
> 1. Verify chữ ký CSR (proof of possession).
> 2. Load Root CA active từ DB, decrypt private key.
> 3. Build cert end-entity với subject + public key lấy từ CSR, SAN copy từ CSR, thêm extensions chuẩn TLS server (BasicConstraints CA=false, KeyUsage digital_signature + key_encipherment, ExtendedKeyUsage serverAuth, CRL Distribution Points, AIA OCSP, SKI, AKI).
> 4. Ký bằng Root CA SHA-256.
> 5. Atomic transaction — INSERT issued_certs + UPDATE csr_requests status='approved'. Nếu 2 admin approve cùng lúc, chỉ 1 thắng."

### 3.5 Refresh queue

**Hình**: CSR chuyển sang status `approved` màu xanh.

---

## Phần 4 — Customer download cert + cert detail (06:30–08:00)

### 4.1 Đăng xuất + login Alice

### 4.2 Xem cert đã cấp (B.6)

**Action**: Sidebar → "Chứng nhận của tôi (B.6)" → bảng hiện 1 cert status `active`.

### 4.3 Xem chi tiết

**Action**: Chọn cert → "📋 Xem chi tiết" → modal CertDetailDialog.

**Tab "Decoded"**: hiển thị Subject, Issuer, Serial, Validity, Public Key, full extensions (SubjectAlternativeName, KeyUsage, ExtendedKeyUsage, CRLDistributionPoints, AuthorityInformationAccess, SKI, AKI).

**Tab "PEM"**: raw PEM.

**Thoại**:
> "Cert đầy đủ extensions chuẩn TLS server. Issuer khớp Root CA subject."

### 4.4 Download

**Action**: Bấm "💾 Tải về (Save as)" → chọn folder → save thành file `.crt`.

**Thoại**:
> "Customer có thể tải cert PEM về để cài lên web server của mình (Nginx, Apache...). Đây là phần khách hàng thực tế dùng."

---

## Phần 5 — Revocation workflow + Publish CRL (08:00–10:30)

### 5.1 Customer yêu cầu thu hồi (B.7)

**Action**: Alice — sidebar → "Yêu cầu thu hồi (B.7)" → chọn cert `myshop.com` → reason `Key đã bị lộ trong server compromise` → bấm "Gửi yêu cầu".

**Hình**: Bảng request hiện 1 row pending.

**Thoại**:
> "B.7 — customer chủ động gửi yêu cầu thu hồi. BOLA-guard: backend validate cert thuộc về requester trước khi cho phép tạo request."

### 5.2 Admin duyệt revoke (A.9)

**Action**: Login admin → Sidebar → "Duyệt thu hồi (A.9)" → chọn request → bấm "✅ Approve" → confirm.

**Thoại**:
> "A.9 — admin duyệt atomic: UPDATE request status='approved' + UPDATE issued_certs.revoked_at + revocation_reason trong cùng 1 transaction. Nếu cert đã bị revoke trước đó (qua A.8 direct revoke), không ghi đè `revoked_at` cũ — preserve audit trail."

### 5.3 Publish CRL (A.10)

**Action**: Sidebar → "Cập nhật CRL (A.10)" → xem panel "Snapshot DB: 1 serial sẽ vào CRL" với warning "⚠ DB có 1 revoked, CRL hiện có 0 → Publish để đồng bộ" → bấm "📢 Publish CRL Now".

**Hình**: Hộp thoại "Đã publish — 1 serial revoked, next_update = ..."

**Thoại**:
> "A.10 — snapshot tất cả `revoked_at IS NOT NULL` từ DB → build CRL → ký bằng Root CA SHA-256 → ghi `certs/crl.pem`. Đồng thời sync `certs/ocsp_db.json` để infra/ocsp_server (legacy) phục vụ trạng thái OCSP realtime."

### 5.4 Verify cert đã revoke

**Action**: Mở terminal phụ → `openssl crl -in certs/crl.pem -text -noout | head -20` (nếu có openssl) hoặc dùng `python -c "from cryptography import x509; ..."` để show CRL signed by Root CA.

---

## Phần 6 — Tra cứu CRL + Upload cert ngoài + Verify (10:30–12:30)

### 6.1 Login customer Bob (B.1)

**Action**: Đăng ký Bob để minh hoạ feature công khai của CRL.

### 6.2 Tra cứu CRL (B.8)

**Action**: Sidebar → "Tra cứu CRL (B.8)" → bảng hiện 1 entry (serial của cert Alice đã revoke).

**Thoại**:
> "B.8 — CRL công khai, ai cũng tra được. Hệ thống enrich CN + owner từ DB để dễ đọc, nhưng entry chính (serial + revocation_date) là dữ liệu PKCS có ký bởi Root CA."

### 6.3 Upload cert ngoài (B.9)

**Action**: Sidebar → "Upload cert ngoài (B.9)" → tab "Upload" → browse file cert đã chuẩn bị trước (cert của Alice đã tải về phần 4) → Preview → Upload + Lưu.

### 6.4 Verify 5 bước

**Action**: Tab "Của tôi" → chọn cert → "🔍 Verify (5 bước)" → hostname `myshop.com` → bấm "▶ Chạy 5 bước".

**Hình**: Log chi tiết 5 bước, banner đỏ FAIL (vì cert đã revoked).

**Thoại**:
> "B.9 — 5 bước verify chuẩn:
> 1. Verify chữ ký cert bằng Root CA public key trong Trust Store.
> 2. Kiểm tra Not Before / Not After.
> 3. Kiểm tra hostname khớp SAN.
> 4. Tải CRL từ URL trong cert, verify chữ ký CRL bằng Root CA, đối chiếu serial.
> 5. Gọi OCSP responder.
>
> Bước 4 và 5 cần `infra/crl_server` + `infra/ocsp_server` đang chạy. Tôi sẽ mở Verification Lab để khởi động."

### 6.5 (Optional) Verification Lab

**Action**: Admin → "Verification Lab" → Start CRL + OCSP server → quay lại customer rerun verify.

---

## Phần 7 — Bảo mật (12:30–14:00)

### 7.1 Encrypt-at-rest

**Action**: Terminal → `python -c "import sqlite3; c = sqlite3.connect('ca_app.db'); rows = c.execute('SELECT id, common_name, length(encrypted_private_key), substr(encrypted_private_key, 1, 30) FROM root_ca').fetchall(); print(rows)"`

**Hình**: Output cho thấy `encrypted_private_key` là bytes ngẫu nhiên, không phải PEM.

**Thoại**:
> "Lưu ý C của đề bài: private key trong DB là ciphertext AES-GCM. Không có header BEGIN PRIVATE KEY. Nếu DB bị leak mà attacker không có master.key thì không decrypt được."

### 7.2 BOLA guard

**Action**: Show code snippet `services/customer_keys.py` — mọi query đều `WHERE owner_id = ?`.

**Thoại**:
> "BOLA / IDOR guard ở mọi customer-facing query. Test suite có test riêng (`test_bola_guard`) xác nhận Bob không truy cập được key của Alice."

### 7.3 Audit log (A.11)

**Action**: Admin sidebar → "Audit log (A.11)" → bảng hiện toàn bộ events.

**Hình**: Login, register, key_generated, csr_submitted, csr_approved, cert_issued, cert_revoked, revoke_requested, revoke_approved, crl_published, external_cert_uploaded — đầy đủ.

**Thoại**:
> "A.11 — audit log ghi mọi hành động chính. Filter theo action key. Best-effort: lỗi audit không phá business flow."

---

## Phần 8 — Closing (14:00–15:00)

### 8.1 Test suite

**Action**: Terminal → chạy 8 test suite.

```powershell
cd d:\repos\X509Certificate
$env:PYTHONIOENCODING='utf-8'
foreach ($t in @("test_m1_foundation","test_m4_ca_admin","test_m5_customer","test_m6_csr_admin","test_m7_cert_lifecycle","test_m8_revocation_crl","test_m9_external_crl","test_scenarios")) {
    python "tests/$t.py"
}
```

**Hình**: 70/70 PASS.

### 8.2 Recap

**Thoại**:
> "Tổng kết:
> - 20/20 yêu cầu chức năng (A.1-11 + B.1-9) + lưu ý C đều có triển khai và test cover.
> - 70/70 test pass.
> - Source code trên GitHub (link trong báo cáo).
> - Stack đơn giản, chạy được offline, không cần internet hay cloud service.
>
> Cảm ơn thầy/cô đã xem!"

---

## Checklist trước khi quay

- [ ] Xoá `ca_app.db`, `master.key`, `certs/` để demo first-run
- [ ] Tắt notification Windows/IDE để không bị popup giữa video
- [ ] Font Montserrat (hoặc các font ưu tiên) đã cài
- [ ] Resolution 1920×1080, scale 100%
- [ ] OBS Studio record 2 màn hình (GUI + terminal) hoặc cuộn qua lại
- [ ] Mic test trước → âm lượng đều
- [ ] Test toàn bộ luồng demo 1 lần trước khi quay chính thức

## Checklist hậu kỳ

- [ ] Upload YouTube **unlisted**
- [ ] Bật subtitle tự động hoặc thêm phụ đề tiếng Việt
- [ ] Thêm timestamp các phần trong description
- [ ] Copy link vào báo cáo Word
