# Outline Báo cáo Kỹ thuật — Đồ án MHUD

> Document này là sườn để bạn copy/paste thành file Word (.docx) khi viết báo cáo. Đã có sẵn nội dung kỹ thuật + bảng + mapping yêu cầu — bạn chỉ cần format lại theo template trường yêu cầu (font Times New Roman 13, margin 2-2-2-3 cm, đánh số trang, mục lục, etc.).

---

## Trang bìa

- **Tên môn**: Mã hoá và Ứng dụng (MHUD)
- **Đề tài**: Hệ thống Quản lý và Cấp phát Chứng nhận X.509 cho dịch vụ Website
- **Sinh viên**: [Họ tên + MSSV]
- **Giảng viên**: [Tên GV]
- **Lớp**: [Mã lớp]
- **Năm học**: 2025–2026
- **Ngày nộp**: [dd/mm/yyyy]

---

## Mục lục (đánh số tự động)

1. Giới thiệu
2. Tổng quan chuẩn X.509 + mô hình PKI
3. Phân tích yêu cầu
4. Thiết kế hệ thống
5. Cài đặt + công nghệ sử dụng
6. Các tính năng đã triển khai
7. Bảo mật + đảm bảo chất lượng
8. Hướng dẫn sử dụng
9. Kết quả + đánh giá
10. Kết luận + hướng phát triển
11. Phụ lục

---

## 1. Giới thiệu (1 trang)

- Bối cảnh: nhu cầu cấp phát chứng chỉ số cho website (HTTPS/TLS).
- Bài toán: xây dựng hệ thống cho CA quản trị + cho khách hàng đăng ký + theo dõi chứng chỉ.
- Mục tiêu đồ án: triển khai end-to-end CA management application theo chuẩn X.509 + PKCS#10 CSR + CRL.
- Phạm vi: desktop application (Tkinter + SQLite), local-first, demo offline.

## 2. Tổng quan X.509 + PKI (2–3 trang)

### 2.1 Chứng nhận X.509 v3

- Định nghĩa, cấu trúc ASN.1 (TBSCertificate + signatureAlgorithm + signatureValue).
- Các trường: Version, Serial, Issuer, Subject, Validity, Public Key, Extensions.
- Extension quan trọng cho TLS server cert: BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName, CRLDistributionPoints, AuthorityInformationAccess (OCSP), SubjectKeyIdentifier, AuthorityKeyIdentifier.

### 2.2 Mô hình PKI

- Vai trò: Subscriber, Relying Party, Certificate Authority, Registration Authority.
- Hierarchy: Root CA (self-signed) → Intermediate CA → End-entity cert. Demo này chỉ có Root CA → End-entity (không có Intermediate cho gọn).
- Trust anchor: Trust Store chứa Root CA cert.

### 2.3 Quy trình cấp phát + thu hồi

- CSR (PKCS#10): subscriber tự sinh keypair → tạo CSR ký bằng private key → CA verify chữ ký CSR (proof of possession) → CA phát hành cert.
- Revocation: 2 cơ chế — CRL (snapshot offline, do CA định kỳ ký) vs OCSP (online realtime). Demo có cả 2.

### 2.4 Thuật toán mật mã sử dụng

- **RSA**: sinh keypair 2048/3072/4096-bit, public exponent 65537.
- **SHA-256**: hash trong chữ ký cert + CRL.
- **PKCS#1 v1.5**: padding cho RSA signature.
- **AES-256-GCM**: mã hoá private key tại rest, AAD bind context.
- **scrypt** (N=16384, r=8, p=1): hash password.

## 3. Phân tích yêu cầu (1–2 trang)

### 3.1 Người dùng

- **Admin (A.1-A.11)**: quản trị hệ thống — 11 chức năng.
- **Customer (B.1-B.9)**: khách hàng xin cấp cert — 9 chức năng.

### 3.2 Mapping yêu cầu → tính năng

> Sao chép từ README section "Tổng kết tính năng đồ án MHUD đã hoàn thành" — bảng 20 dòng A.1-11 + B.1-9 + lưu ý C.

### 3.3 Yêu cầu phi chức năng

- Bảo mật: encrypt-at-rest dữ liệu nhạy cảm (lưu ý C).
- Đảm bảo: chống user enumeration (login timing), BOLA/IDOR guard, audit log đầy đủ.
- UX: validate input, error message rõ ràng, status có màu.

## 4. Thiết kế hệ thống (3–4 trang)

### 4.1 Kiến trúc tổng thể

Diagram 3 layer:

```
┌──────────────────────────────────────────┐
│ UI Layer       (Tkinter — admin/customer)│
├──────────────────────────────────────────┤
│ Service Layer  (auth, ca_admin, csr,     │
│                 cert_lifecycle, revoke,  │
│                 crl_publish, audit, ...) │
├──────────────────────────────────────────┤
│ Core Layer     (ca, cert_builder, csr,   │
│                 crl, verify, encryption) │
├──────────────────────────────────────────┤
│ DB Layer       (SQLite, 9 tables)        │
└──────────────────────────────────────────┘
```

### 4.2 Cấu trúc thư mục

> Copy từ README section "Cấu trúc mới".

### 4.3 Schema database

> Copy từ src/db/schema.sql — 9 bảng, mô tả từng bảng + relationship.

ERD diagram:
- `users` (1-N) `csr_requests`, `customer_keys`, `issued_certs`, `revocation_requests`, `external_certs`, `audit_log`
- `csr_requests` (1-1) `issued_certs` (qua `csr_request_id` FK)
- `issued_certs` (self-ref) qua `renewed_from_id` cho chain renew
- `issued_certs` (1-N) `revocation_requests`

### 4.4 Mô hình trạng thái

#### 4.4.1 CSR

```
   submit          approve
[pending] ─────► [approved] → issued_certs row
    │
    │ reject (with reason)
    └────────► [rejected]
```

#### 4.4.2 Cert lifecycle

```
              ┌───── renew (new cert with same pubkey) ─────┐
              │                                              ▼
[active] ──── │ ─────── time passes ──────► [expired]      [new active]
              │
              │ revoke / revoke_request approved
              └────────► [revoked]
```

Status `expired` / `revoked` / `active` được compute động từ `revoked_at` + `not_valid_after`, không lưu cột status.

#### 4.4.3 Revocation request

Tương tự CSR — pending → approved/rejected.

### 4.5 Mã hoá at-rest (lưu ý C)

- **Master key**: 32 bytes ngẫu nhiên, sinh lần đầu, lưu trong file `master.key` (gitignored). Production thực phải dùng HSM/KMS.
- **AES-256-GCM**:
  - Nonce 12 bytes random per encrypt.
  - AAD = `f"{table}:{role}"` (vd `root_ca`, `customer_keys:42`) để bind ciphertext với context, chống copy-paste ciphertext giữa các record.
  - Auth tag 16 bytes tự động append sau ciphertext.
- **scrypt** cho password hash: format self-describing `scrypt$N$r$p$salt_hex$hash_hex` cho phép upgrade tham số sau này.

## 5. Cài đặt + công nghệ (1–2 trang)

### 5.1 Stack

- **Python 3.14**: ngôn ngữ chính. Có sẵn `tkinter`, `sqlite3`, `hashlib.scrypt` trong stdlib.
- **cryptography ≥ 41**: cho X.509, CRL, CSR, RSA, AES-GCM.
- **Tkinter + ttk (theme `clam`)**: GUI desktop, không cần extra dependency.

### 5.2 Dependencies (`requirements.txt`)

```
cryptography>=41.0.0
```

Một dòng duy nhất — toàn bộ còn lại dùng stdlib.

### 5.3 Cấu trúc package

> Copy từ README "Cấu trúc mới" — 7 subpackage: core, db, services, infra, ui (admin + customer), legacy.

## 6. Các tính năng đã triển khai (4–5 trang)

> Mỗi tính năng A.x / B.x dành ~1 đoạn ngắn: mô tả + module liên quan + screenshot UI.

### 6.1 Quản trị (Admin) — A.1-A.11

- A.1 Đăng nhập, A.2 đổi mật khẩu
- A.3 Cấu hình hệ thống
- A.4-A.5 Sinh Root CA
- A.6-A.7 Duyệt CSR
- A.8 Quản lý cert: revoke + renew
- A.9 Duyệt yêu cầu thu hồi
- A.10 Publish CRL
- A.11 Audit log

### 6.2 Khách hàng (Customer) — B.1-B.9

- B.1-B.3 Đăng ký + đăng nhập + đổi mật khẩu
- B.4 Sinh keypair
- B.5 Submit CSR
- B.6 Xem + tải cert
- B.7 Yêu cầu thu hồi
- B.8 Tra cứu CRL
- B.9 Upload cert ngoài + verify 5 bước

### 6.3 Verification Lab (legacy demo, bonus)

5 bước verify + lifecycle/renew/pin rotation — giữ làm minh hoạ giảng bài.

## 7. Bảo mật + Đảm bảo chất lượng (2 trang)

### 7.1 Encrypt-at-rest

- Mọi private key đều mã hoá AES-GCM. Test `[encrypt-at-rest]` đọc raw bytes từ DB và assert không chứa `BEGIN PRIVATE KEY` marker.

### 7.2 BOLA / IDOR

- Mọi customer-facing query đều `WHERE owner_id = ?` hoặc tương đương.
- Test `[bola-guard]` xác nhận Bob không truy cập được key của Alice.

### 7.3 Race condition

- approve_csr + approve_revocation đều dùng transaction với re-check status — chống 2 admin approve cùng lúc.

### 7.4 User enumeration

- `login()` luôn gọi `verify_password` kể cả khi user không tồn tại — tránh timing leak. Error message generic ("Sai username hoặc password").

### 7.5 Atomicity

- Mọi DB operation có nhiều bước đều bọc trong `transaction()` context manager với BEGIN/COMMIT/ROLLBACK rõ ràng.

### 7.6 Test suite

- 8 test suite, 70 test case, 100% pass.

| Suite | Test count | Phạm vi |
|---|---|---|
| M1 foundation | 8 | DB + scrypt + AES-GCM + auth + audit + config |
| M4 CA admin | 7 | Root CA + encrypt-at-rest + AAD binding |
| M5 customer | 11 | Keypair + CSR + BOLA |
| M6 CSR admin | 8 | Approve/reject + cert issue + tampered CSR |
| M7 cert lifecycle | 8 | Revoke + renew + status compute |
| M8 revocation+CRL | 11 | Revoke workflow + CRL signed |
| M9 external+CRL lookup | 8 | Parse PEM/DER + BOLA + CRL enrich |
| Legacy lab | 9 | 5-step verify + lifecycle/renew |

## 8. Hướng dẫn sử dụng (1–2 trang)

### 8.1 Cài đặt

```powershell
git clone <repo>
cd X509Certificate
pip install -r requirements.txt
python main.py
```

### 8.2 Lần đầu chạy

- Tự tạo `ca_app.db`, `master.key`, account admin mặc định `admin/Admin@123`.
- Đổi mật khẩu admin ngay.

### 8.3 Quy trình điển hình

1. Admin: Sinh Root CA (A.4-5)
2. Customer: Đăng ký (B.1) → Sinh keypair (B.4) → Submit CSR (B.5)
3. Admin: Duyệt CSR + phát hành cert (A.6-7)
4. Customer: Tải cert (B.6) hoặc yêu cầu thu hồi (B.7)
5. Admin: Duyệt revoke (A.9) → Publish CRL (A.10)

### 8.4 Backup

```powershell
python scripts/backup_db.py
# Tạo backup/<timestamp>/ca_app.db + master.key + certs/
```

### 8.5 Chạy test

```powershell
$env:PYTHONIOENCODING='utf-8'
python tests/test_m1_foundation.py
python tests/test_m4_ca_admin.py
# ... v.v.
```

## 9. Kết quả + Đánh giá (1 trang)

### 9.1 Đạt được

- 20/20 yêu cầu chức năng (A.1-11 + B.1-9) + lưu ý C đều hoàn thành.
- 70/70 test pass.
- Encrypt-at-rest đúng chuẩn AES-GCM với AAD binding.
- BOLA-guard mọi customer endpoint.
- Atomic transactions cho mọi workflow approve.

### 9.2 Hạn chế

- Master key lưu plain trong file (production nên dùng HSM/KMS).
- OCSP responder JSON (không phải ASN.1 chuẩn) — chỉ minh hoạ logic.
- Chưa có Intermediate CA chain — Root CA ký trực tiếp end-entity.
- Tkinter UI không có true glassmorphism / shadow — limitation của framework.

### 9.3 Bài học kinh nghiệm

- Encrypt-at-rest cần AAD để bind context, không chỉ dùng nonce ngẫu nhiên.
- Race condition cần re-check status trong transaction.
- BOLA-guard phải ở mọi tầng (UI + service + DB query).
- Test infrastructure cần fixture isolation (mỗi test tmpdir riêng).

## 10. Kết luận + Hướng phát triển (0.5 trang)

### 10.1 Kết luận

Đồ án đã triển khai đầy đủ một hệ thống CA Management theo chuẩn X.509 v3 + PKCS#10 CSR + CRL chuẩn ASN.1. Tất cả yêu cầu chức năng + bảo mật đều có test cover. Stack đơn giản, dễ deploy offline.

### 10.2 Hướng phát triển

- **Intermediate CA chain**: thêm tầng Intermediate CA cho realistic hơn.
- **OCSP chuẩn ASN.1**: thay JSON bằng OCSP request/response binary.
- **Backup/Restore master.key qua HSM/KMS**: thay file phẳng.
- **Multi-admin với role-based ACL**: hiện tại mọi admin có toàn quyền.
- **Web UI**: chuyển sang React + Flask/FastAPI để remote access.
- **HSM integration**: lưu Root CA private key trong physical HSM (PKCS#11).

## 11. Phụ lục

### A. Cấu trúc thư mục đầy đủ

> Copy từ README.

### B. Schema SQL đầy đủ

> Copy từ `src/db/schema.sql`.

### C. Action keys của audit log

> Copy từ `services/audit.Action`.

### D. Test results

Copy output `[Kết quả: X PASS / 0 FAIL]` của từng suite.

### E. Link demo video

[YouTube unlisted: ...]

### F. Link GitHub repository

[github.com/...]
