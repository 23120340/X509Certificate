# Hệ thống Quản lý và Cấp phát Chứng nhận X.509

**Đồ án Mã hoá và Ứng dụng (MHUD)** — Hệ thống Web/Desktop quản lý Certificate Authority đầy đủ, hỗ trợ phát hành + thu hồi chứng chỉ X.509 v3 cho dịch vụ Website theo chuẩn PKCS#10 CSR + CRL.

> **Trạng thái**: ✅ **Hoàn thành** — 20/20 yêu cầu (A.1-11 + B.1-9 + lưu ý C) đã triển khai, **70/70 test pass** trên 8 test suite. Phần verify 5 bước + lifecycle/renew demo (Verification Lab) cũng giữ làm minh hoạ giảng bài.

## Tóm tắt

- **Admin**: cấu hình hệ thống, sinh + quản lý Root CA, duyệt CSR + phát hành cert, revoke/renew, duyệt yêu cầu thu hồi, publish CRL, xem audit log.
- **Customer**: đăng ký, sinh keypair RSA, submit CSR cho domain, xem + tải cert, yêu cầu thu hồi, tra cứu CRL công khai, upload cert ngoài để verify 5 bước.
- **Bảo mật**: private key mã hoá AES-256-GCM với AAD context, password hash scrypt, BOLA-guard mọi customer endpoint, atomic transaction cho mọi workflow approve, audit log đầy đủ.
- **Stack tối giản**: Python 3.14 + Tkinter + SQLite + `cryptography` — chỉ 1 dependency, chạy offline.

> Verification Lab (legacy) — demo 5 bước verify + lifecycle/renew + pin rotation — truy cập từ Admin Dashboard. Mục tiêu: minh hoạ cách client xác thực cert + cơ chế CRL vs OCSP.

## Mô hình tin cậy

```text
Root CA (self-signed)
    │
    ├── ký Server Certificate    (issuer = Root CA subject)
    └── ký CRL                   (CRL issuer = Root CA subject)

Trust Store của client
    └── chứa Root CA certificate

Client verify:
    server_cert.signature  ──verify bằng──►  Root CA public key (trong Trust Store)
    crl.signature          ──verify bằng──►  Root CA public key (trong Trust Store)
```

Demo bỏ qua chain trung gian (không có Intermediate CA) nhưng giữ đúng ý tưởng Root CA + Trust Store của X.509.

## Cấu trúc project

```text
X509Certificate/
├── main.py                       # Entry — launches CA management app
├── requirements.txt              # 1 dep: cryptography
├── README.md
├── .gitignore
├── ca_app.db                     # Runtime SQLite (gitignored)
├── master.key                    # Runtime AES master key (gitignored)
├── docs/
│   ├── DEMO_SCRIPT.md            # Kịch bản video 15p cho CA app
│   ├── TECHNICAL_REPORT_OUTLINE.md  # Sườn báo cáo Word
│   └── DEMO_SCRIPT_LEGACY_LAB.md # Kịch bản Verification Lab cũ
├── scripts/
│   └── backup_db.py              # Backup DB + master.key + certs/ với manifest
├── src/
│   ├── core/                     # Crypto primitives
│   │   ├── ca.py                 #   Root CA (load/create + trust store)
│   │   ├── cert_builder.py       #   Build cert end-entity (CSR / renew)
│   │   ├── csr.py                #   PKCS#10 build/parse/verify
│   │   ├── crl.py                #   CRL build/sign + OCSP DB helper
│   │   ├── verify.py             #   5-step client verification
│   │   └── encryption.py         #   AES-256-GCM + scrypt password hash
│   ├── db/
│   │   ├── schema.sql            #   9 tables
│   │   └── connection.py         #   FK ON + WAL + transaction ctx
│   ├── services/                 # Business logic
│   │   ├── auth.py               #   Register/login/change_password
│   │   ├── system_config.py      #   A.3 — default key_size, validity, etc.
│   │   ├── ca_admin.py           #   A.4-5 — Root CA encrypt-at-rest
│   │   ├── customer_keys.py      #   B.4 — RSA keypair (encrypt AAD=key_id)
│   │   ├── csr_workflow.py       #   B.5 — submit CSR
│   │   ├── csr_admin.py          #   A.6-7 — approve/reject + issue cert
│   │   ├── cert_lifecycle.py     #   A.8 / B.6 — list/revoke/renew
│   │   ├── revocation_workflow.py #  B.7 / A.9 — revoke request workflow
│   │   ├── crl_publish.py        #   A.10 — snapshot DB → signed CRL
│   │   ├── external_certs.py     #   B.9 — upload + parse 3rd-party cert
│   │   └── audit.py              #   A.11 — write_audit + Action catalog
│   ├── ui/
│   │   ├── app.py                # Tk root + router + bootstrap
│   │   ├── login.py              # Login + register tab
│   │   ├── common.py             # ChangePwDialog, header bar, CertDetailDialog
│   │   ├── theme.py              # Design system (M10)
│   │   ├── admin/                # 7 dashboard pages cho admin
│   │   └── customer/             # 6 dashboard pages cho customer
│   ├── infra/                    # HTTP servers cho CRL + OCSP
│   │   ├── crl_server.py
│   │   └── ocsp_server.py
│   └── legacy/                   # Verification Lab cũ (giữ để minh hoạ)
│       ├── server_manager.py
│       └── lifecycle_demo.py
├── tests/                        # 8 test suite — 70 test, 100% pass
│   ├── test_m1_foundation.py
│   ├── test_m4_ca_admin.py
│   ├── test_m5_customer.py
│   ├── test_m6_csr_admin.py
│   ├── test_m7_cert_lifecycle.py
│   ├── test_m8_revocation_crl.py
│   ├── test_m9_external_crl.py
│   └── test_scenarios.py         # Legacy verify lab
├── certs/                        # Runtime — Root CA cert PEM + CRL + OCSP DB
│   ├── crl.pem
│   ├── ocsp_db.json
│   └── trust_store/root_ca.crt
└── backups/                      # Output của scripts/backup_db.py (gitignored)
    └── <timestamp>/
        ├── ca_app.db
        ├── master.key
        ├── certs/
        ├── schema.sql
        └── backup_manifest.json
```

## Cài đặt

```bash
pip install -r requirements.txt
```

Tkinter có sẵn trong Python standard library trên hầu hết các bản cài đặt Python desktop.

## Chạy chương trình

```bash
python main.py
```

Chạy từ thư mục gốc project. `main.py` tự thêm `src/` vào `sys.path` nên các module trong `src/` import được nhau bình thường.

Chạy test end-to-end:

```powershell
$env:PYTHONIOENCODING='utf-8'
python tests/test_scenarios.py        # demo cũ: 5 bước verify + lifecycle/renew
python tests/test_m1_foundation.py    # M1: DB + auth + encryption + audit + config
```

## Lộ trình mở rộng theo đồ án MHUD (CA Management)

Demo hiện tại đáp ứng khoảng 25% spec đồ án (phần *crypto core + client verify*). Đang refactor dần thành hệ thống CA quản lý đầy đủ (Admin + Customer, DB, auth, CSR workflow). Tiến độ:

| Mốc | Nội dung | Trạng thái |
|---|---|---|
| M0 | Cấu trúc thư mục mới (`src/core`, `src/db`, `src/services`, `src/ui/{admin,customer}`, `src/infra`, `src/legacy`) | ✓ Done |
| M1 | DB schema 9 bảng + connection helper + AES-256-GCM encryption-at-rest + scrypt password hashing + auth service + audit log + system_config | ✓ Done |
| M2 | Move 8 modules vào subpackage: `issuer→core/ca`, `cert_generator→core/cert_builder`, `crl_manager→core/crl`, `client→core/verify`, `crl_server/ocsp_server→infra/`, `server_manager+gui→legacy/`. Tests cũ vẫn xanh, zero regression. | ✓ Done |
| M3 | UI shell: `ui/app.py` (Tk single-root router + bootstrap), `ui/login.py` (login + register customer), `ui/admin/dashboard.py` (sidebar 9 mục, A.11 audit log + Verification Lab đã wired), `ui/customer/dashboard.py` (sidebar 7 mục). Đổi mật khẩu (A.2/B.3) hoạt động. | ✓ Done |
| M4 | A.3 system_config UI (form 5 trường + whitelist + audit) + A.4-5 Root CA (`services/ca_admin.py`: sinh keypair + cert, encrypt private key AES-GCM AAD=`root_ca`, lưu vào bảng `root_ca`; UI có dialog sinh + bảng history + nút publish ra Trust Store). | ✓ Done |
| M5 | B.4 customer keypair (`services/customer_keys.py`: sinh RSA, encrypt private key AES-GCM AAD=`customer_keys:{id}`, BOLA guard owner_id) + B.5 CSR submit (`core/csr.py` build/parse/verify PKCS#10; `services/csr_workflow.py` submit/list/cancel) + UI MyKeys + CSR Submit + audit. | ✓ Done |
| M6 | A.6-7 admin duyệt CSR (`services/csr_admin.py` list_pending/approve/reject + verify CSR signature trước approve + atomic INSERT issued_certs + UPDATE status, `core/cert_builder.issue_cert_from_csr` build cert end-entity ký bởi Root CA active) + UI `csr_queue_view.py` (filter status + Approve/Reject dialog + audit) | ✓ Done |
| M7 | B.6 customer xem/tải cert + A.8 admin revoke/renew (`services/cert_lifecycle.py`: list/detail BOLA-guard + compute_status active/expired/revoked + revoke + renew giữ public key của customer; `core/cert_builder.reissue_cert_for_renewal`) + UI `cert_mgmt_view.py` (admin) + `my_certs_view.py` (customer) + `CertDetailDialog` shared trong `ui/common.py` (decoded extensions + PEM + Save As) | ✓ Done |
| M8 | B.7 customer yêu cầu thu hồi (`services/revocation_workflow.py`: submit + BOLA + duplicate guard + cert chưa revoked check) + A.9 admin duyệt (atomic UPDATE request + cert, không ghi đè revoked_at cũ) + A.10 publish CRL (`services/crl_publish.py`: snapshot DB → build CRL ký Root CA → ghi crl.pem + sync ocsp_db.json cho infra) + 3 UI views + audit log | ✓ Done |
| M9 | B.8 tra CRL công khai (`services/crl_publish.list_crl_entries` parse file CRL + enrich CN/owner từ DB) + B.9 upload cert ngoài (`services/external_certs.py`: parse PEM/DER + SHA-256 fingerprint + BOLA + UNIQUE per uploader) + UI verify dialog reuse `core.verify.verify_certificate_full` (5 bước) | ✓ Done |
| M10 | UI design system (`ui/theme.py` — color tokens navy+slate, font scale với Clash Display/Hinato/Montserrat fallback, 4/8 spacing rhythm, Primary/Accent/Danger/Ghost button variants, status colors cho Treeview), demo script + technical report outline + `scripts/backup_db.py` (snapshot DB + master.key + certs + SHA-256 manifest), README polish | ✓ Done |

### M1 — Foundation (đã làm)

- **`src/db/schema.sql`** — 9 bảng: `users`, `system_config`, `root_ca`, `customer_keys`, `csr_requests`, `issued_certs`, `revocation_requests`, `audit_log`, `external_certs`.
- **`src/db/connection.py`** — `init_db()`, `get_conn()` (foreign_keys=ON, WAL), `transaction()` context manager.
- **`src/core/encryption.py`** — encryption-at-rest (đáp ứng lưu ý C đồ án):
  - `hash_password` / `verify_password` (scrypt N=2¹⁴, r=8, salt 16B, format self-describing).
  - `encrypt_blob` / `decrypt_blob` (AES-256-GCM, nonce 12B, hỗ trợ AAD để bind ciphertext với context).
  - Master key 32 bytes lưu trong file `master.key` ở project root (gitignored). **Lưu ý**: production thực phải dùng HSM/KMS.
- **`src/services/auth.py`** — `register_user`, `login`, `change_password`, `seed_admin_if_empty`. Chống user-enumeration: cùng message generic cho mọi lỗi auth, vẫn chạy verify khi user không tồn tại để timing không leak.
- **`src/services/audit.py`** — `write_audit()` best-effort (lỗi DB không phá business flow), `list_recent()` filter theo actor/action. Catalog action keys trong class `Action`.
- **`src/services/system_config.py`** — `seed_defaults()` (sig_algorithm, hash_algorithm, default_key_size=2048, default_validity_days=365, root_ca_validity_days=3650), `get/set` với whitelist guard.
- **`tests/test_m1_foundation.py`** — 8 smoke test: schema, scrypt roundtrip + salt random, AES-GCM roundtrip + AAD + tamper detection, register/login/duplicate, change_password, seed_admin idempotent, audit write/filter, config seed/whitelist.

### M3 — UI shell (đã làm)

- **`src/ui/app.py`** — `App` class quản lý Tk root duy nhất + swap content frame theo page (pattern SPA). Bootstrap chạy `init_db → seed_defaults → seed_admin_if_empty(admin/Admin@123)` ở lần đầu.
- **`src/ui/login.py`** — Notebook 2 tab: "Đăng nhập" (cho cả admin + customer) và "Đăng ký (Customer)". Sau auth thành công gọi `app.on_login_success(user)` → route theo role.
- **`src/ui/common.py`** — `ChangePasswordDialog` modal (A.2/B.3), `build_dashboard_header`, `coming_soon_frame` placeholder.
- **`src/ui/admin/dashboard.py`** — Sidebar 9 mục theo A.1-11. Đã wire: Tổng quan, Audit log (A.11), Verification Lab (mở legacy demo qua Toplevel). Còn lại hiển thị placeholder + milestone.
- **`src/ui/admin/audit_view.py`** — Bảng Treeview 200 event gần nhất, filter theo action, refresh button.
- **`src/ui/customer/dashboard.py`** — Sidebar 7 mục theo B.1-9. Đã wire: Tổng quan + Đổi mật khẩu. Còn lại placeholder.
- **`src/legacy/lifecycle_demo.py`** — Thêm `launch_as_toplevel(parent)` để embed vào Admin Dashboard.

### Tài khoản mặc định lần đầu

Khi chạy `python main.py` lần đầu, hệ thống tự tạo:
- Username: `admin`
- Password: `Admin@123`
- Role: `admin`

→ **Đổi mật khẩu ngay** sau khi đăng nhập (nút "Đổi mật khẩu" ở header). Customer tự đăng ký qua tab "Đăng ký (Customer)" ở màn hình login.

### M4 — System config + Root CA (đã làm)

- **`src/services/ca_admin.py`** — Root CA service:
  - `create_root_ca(common_name, key_size, validity_days, created_by, db_path)` — sinh RSA keypair + Root cert self-signed, **encrypt private key bằng AES-256-GCM (AAD=`root_ca`)** rồi lưu vào bảng `root_ca`. Tự deactivate Root CA cũ (1 row active mỗi lúc).
  - `get_active_root_ca()` — metadata + cert PEM (không decrypt key).
  - `load_active_root_ca_with_key()` — decrypt → return `(cert_obj, private_key_obj)`. Dùng khi ký cert mới, ký CRL.
  - `publish_active_to_trust_store(dir)` — ghi cert PEM ra `certs/trust_store/root_ca.crt` để client/CRL server tải.
  - `list_root_ca_history()` — toàn bộ Root CA đã từng có (active + retired).
- **`src/ui/admin/system_config_view.py`** — form 5 trường (sig_algorithm, hash_algorithm, default_key_size, default_validity_days, root_ca_validity_days) với dropdown + validate + diff-aware save (chỉ insert audit khi có thay đổi thật).
- **`src/ui/admin/root_ca_view.py`** — view có:
  - Phần *active*: hiển thị info nếu có, hoặc CTA "Sinh Root CA" nếu chưa.
  - Phần *history*: bảng tất cả Root CA + cờ active.
  - Dialog **Sinh Root CA mới**: nhập CN + key_size (radio 2048/3072/4096) + validity_days. Cảnh báo đỏ khi rotate.
  - Nút **Publish ra Trust Store** xuất `root_ca.crt` ra `certs/trust_store/`.
- **`tests/test_m4_ca_admin.py`** — 7 test: create, encrypted-at-rest (verify DB chứa ciphertext không phải PEM), rotate (deactivate cũ), input validation, load-empty-error, publish, AAD binding (decrypt sai AAD raise InvalidTag).

Tính năng nay đã dùng được trong admin UI:
- A.2 Đổi mật khẩu ✓
- A.3 Cấu hình hệ thống ✓
- A.4 Sinh keypair Root CA ✓
- A.5 Phát sinh Root Certificate ✓
- A.11 Audit log ✓
- Verification Lab ✓

### M5 — Customer keypair + CSR submit (đã làm)

- **`src/core/csr.py`** — PKCS#10 primitives:
  - `build_csr(private_key, common_name, san_list)` — tự thêm CN vào SAN (chuẩn TLS hiện đại), ký SHA256.
  - `parse_csr(pem_or_der)` — load CSR, auto-detect format.
  - `verify_csr_signature(csr)` — verify chữ ký bằng public key trong CSR (proof of possession).
  - `csr_to_pem`, `get_csr_common_name`, `get_csr_san_dns` — helpers cho admin queue.

- **`src/services/customer_keys.py`** — keypair lifecycle:
  - `generate_keypair(owner_id, name, key_size, db_path)` — sinh RSA, encrypt private key với **AAD=`customer_keys:{id}`** (bind theo id row, copy ciphertext sang row khác không decrypt được).
  - `list_keys`, `get_key_meta`, `load_private_key`, `delete_key` — mọi hàm WHERE owner_id=? để chống BOLA/IDOR. `delete_key` refuse nếu key đang được CSR tham chiếu.
  - Constraint: `UNIQUE(owner_id, name)` trong DB → user A và B có thể cùng tên "main".

- **`src/services/csr_workflow.py`** — submit/list/cancel (admin side để M6):
  - `submit_csr(requester_id, customer_key_id, common_name, san_list, db_path)` — kiểm tra ownership của key, decrypt key, build CSR PEM, lưu DB với `status='pending'`.
  - `list_my_csr`, `get_my_csr_by_id` — luôn filter theo `requester_id`.
  - `cancel_csr` — đổi pending → rejected với reason="cancelled by requester".

- **`src/ui/customer/my_keys_view.py`** — bảng keypair + dialog sinh + xem public PEM + xóa.
- **`src/ui/customer/csr_submit_view.py`** — form submit CSR (chọn keypair + CN + SAN) + bảng CSR của mình (status có màu) + xem CSR PEM + hủy CSR.

- **`tests/test_m5_customer.py`** — 11 test: generate/load, encrypt-at-rest, AAD bind theo id, BOLA guard (Bob không truy cập key Alice), duplicate-name, CSR build+verify+SAN, persist CSR + roundtrip PEM, ownership check (Alice không submit CSR với key Bob), CN validation (CSV/wildcard), cancel CSR, delete-key blocked khi đang được CSR ref.

Tính năng dùng được trong customer UI:
- B.1 Đăng ký ✓
- B.2 Đăng nhập ✓
- B.3 Đổi mật khẩu ✓
- B.4 Sinh keypair RSA ✓
- B.5 Submit CSR ✓
- B.6 (1 phần) Xem CSR đã submit + status ✓

**Tổng test suite:** 35/35 PASS (M1: 8, M4: 7, M5: 11, Legacy: 9).

### M6 — Admin duyệt CSR + phát hành cert (đã làm)

- **`src/core/cert_builder.issue_cert_from_csr(csr, ca_cert, ca_key, validity_days, ocsp_url, crl_url)`** — build cert end-entity:
  - subject + public_key lấy từ CSR (proof of possession — đảm bảo customer thực sự sở hữu key).
  - issuer = Root CA subject; serial random; SAN copy từ CSR; thêm `KeyUsage(digital_signature, key_encipherment)`, `ExtendedKeyUsage(SERVER_AUTH)`, `BasicConstraints(ca=False)`, `CRLDistributionPoints`, `AuthorityInformationAccess(OCSP)`, SKI + AKI.
  - Ký bằng Root CA private key (SHA256).

- **`src/services/csr_admin.py`**:
  - `list_pending_csr`, `list_all_csr(status?)`, `get_csr_detail` — admin xem được mọi CSR (JOIN với users để có username).
  - `reject_csr(csr_id, admin_id, reason, db_path)` — reason bắt buộc, max 500 ký tự; chỉ áp dụng status='pending'.
  - `approve_csr(csr_id, admin_id, validity_days, db_path)`:
    1. Read CSR + check pending.
    2. Parse CSR PEM, **verify chữ ký CSR** (`verify_csr_signature`) — nếu lệch raise CSRAdminError.
    3. Load Root CA active (`load_active_root_ca_with_key` → decrypt key).
    4. Build cert + sign.
    5. Atomic transaction: re-check status, INSERT `issued_certs`, UPDATE `csr_requests.status='approved'` — chống race 2 admin approve cùng lúc.

- **`src/ui/admin/csr_queue_view.py`** — bảng với filter status (pending/approved/rejected/all), status có màu, dialog Xem chi tiết / Approve (nhập validity_days, default từ system_config) / Reject (textarea reason bắt buộc). Audit log ghi cả `CSR_APPROVED` lẫn `CERT_ISSUED` khi approve.

- **`tests/test_m6_csr_admin.py`** — 8 test: approve-happy (cert ký bởi Root CA verify OK), SAN copy, cert public key match customer keypair, reject (+ double-reject + empty reason guard), approve khi không có Root CA → error, double-approve → error, tampered CSR signature → reject, list_pending/filter chính xác.

Tính năng nay đã dùng được trong admin UI:
- A.6 Từ chối CSR ✓
- A.7 Phê duyệt + phát hành cert ✓

**Tổng test suite hiện tại:** 43/43 PASS (M1: 8, M4: 7, M5: 11, M6: 8, Legacy: 9).

### M7 — Cert lifecycle (đã làm)

- **`src/core/cert_builder.py`**:
  - Refactor: extract `_build_end_entity_cert` (helper chung) — chứa logic dựng cert end-entity với extensions chuẩn TLS server (BasicConstraints ca=False, KeyUsage, ExtendedKeyUsage SERVER_AUTH, CRL Distribution Points, AIA OCSP, SKI, AKI).
  - `issue_cert_from_csr` và `reissue_cert_for_renewal` đều gọi helper này → tránh duplicate ~30 dòng.

- **`src/services/cert_lifecycle.py`**:
  - `list_certs_for_owner(owner_id, db_path, status?)` — customer chỉ thấy cert của mình (BOLA-guard).
  - `list_all_certs(db_path, status?)` — admin xem tất cả; status filter `active/expired/revoked/all` được compute từ `revoked_at` + `not_valid_after` so với `now`.
  - `get_cert_detail(cert_id, db_path, owner_id?)` — nếu `owner_id != None` enforce ownership; trả về None nếu không thuộc.
  - `revoke_cert(cert_id, admin_id, reason, db_path)` — set `revoked_at` + `revocation_reason`; reason bắt buộc, refuse double-revoke. (Snapshot vào CRL/OCSP sẽ làm ở M8.)
  - `renew_cert(cert_id, admin_id, validity_days, db_path)` — load cert cũ + Root CA active, gọi `reissue_cert_for_renewal` để build cert mới giữ **subject + public_key** của cert cũ (admin không có private key của customer), INSERT row mới với `renewed_from_id = cert_id` cũ. Cert cũ KHÔNG bị revoke tự động.

- **`src/ui/common.CertDetailDialog`** — modal shared cho cả admin + customer:
  - Header: ID, serial, domain, owner, status, validity, issued_at, renewed_from, revoked_at + reason.
  - Tab "Decoded": parse cert PEM, hiển thị subject/issuer/serial/validity/public key + extensions.
  - Tab "PEM": raw text + nút Copy + Save As.

- **`src/ui/admin/cert_mgmt_view.py`** — bảng tất cả cert (status có màu), filter status, actions: Xem chi tiết / Revoke (reason bắt buộc) / Renew (validity_days, default từ system_config). Audit log ghi `CERT_REVOKED` + `CERT_RENEWED`.

- **`src/ui/customer/my_certs_view.py`** — bảng cert của user, filter status, actions: Xem chi tiết / Tải về (Save as PEM). Owner_id check trong mọi service call.

- **`tests/test_m7_cert_lifecycle.py`** — 8 test: list isolation (BOLA), compute_status 3 nhánh + filter, revoke happy + reason + double-revoke, renew happy (public key + subject + SAN giữ nguyên, ký Root CA verify OK), renew cert đã revoked → error, renew khi không có Root CA → error, get_cert_detail ownership enforce, renew-chain qua 3 lần.

Tính năng đã dùng được:
- Admin: A.1-7, **A.8 revoke + renew**, A.11, Verification Lab.
- Customer: B.1-5, **B.6 xem + tải cert**.

**Tổng test suite hiện tại:** 51/51 PASS (M1: 8, M4: 7, M5: 11, M6: 8, M7: 8, Legacy: 9).

### M8 — Revocation workflow + Publish CRL (đã làm)

- **`src/services/revocation_workflow.py`** — submit/list/approve/reject:
  - `submit_revoke_request(cert_id, requester_id, reason, db_path)` — customer side. Validate: cert thuộc requester (BOLA), cert chưa revoked, không có pending request trùng cert.
  - `list_my_revocation_requests(requester_id, db_path)` — customer xem.
  - `list_pending_revocations` / `list_all_revocations(status?)` — admin queue + filter.
  - `approve_revocation(req_id, admin_id, db_path)` — atomic: UPDATE request `status='approved'` + UPDATE `issued_certs.revoked_at + revocation_reason` nếu cert chưa revoked. Trả về `cert_was_revoked` để caller biết có cần audit `CERT_REVOKED` không.
  - `reject_revocation(req_id, admin_id, reason, db_path)` — reason bắt buộc; ghi nối reason vào `reason` column để giữ history.

- **`src/services/crl_publish.py`** — A.10:
  - `snapshot_revoked_serials(db_path)` — SELECT serial_hex của tất cả `revoked_at IS NOT NULL`, parse → list[int].
  - `publish_crl(admin_id, db_path, crl_path, ocsp_db_path, validity_days)` — load Root CA active → `core/crl.build_crl` → save_crl (cho infra/crl_server) + save_revoked_list JSON (cho infra/ocsp_server). Validity mặc định 7 ngày.
  - `get_published_crl_info(crl_path)` — đọc lại file CRL hiện hành (issuer, this_update, next_update, count, file_size) cho UI.

- **`src/ui/customer/revoke_request_view.py`** — form chọn cert active + reason + submit; bảng request đã gửi với status có màu.
- **`src/ui/admin/revoke_queue_view.py`** — bảng tất cả request (filter status) + Approve (set cert revoked + audit `REVOKE_APPROVED` + `CERT_REVOKED`) + Reject (reason bắt buộc + audit `REVOKE_REJECTED`).
- **`src/ui/admin/crl_publish_view.py`** — hiển thị metadata CRL hiện hành + snapshot DB (preview các serial sẽ vào CRL + diff cảnh báo nếu CRL out-of-sync) + nút "Publish CRL Now" + audit `CRL_PUBLISHED`.

- **`tests/test_m8_revocation_crl.py`** — 11 test: submit happy, validation 4 nhánh (BOLA/empty/duplicate-pending/already-revoked), approve mark cert revoked, approve khi cert đã revoked trước đó (không ghi đè), reject + reason required, double-approve blocked, snapshot serials đúng, publish CRL file (chữ ký Root CA verify OK + OCSP DB sync), publish khi không có Root CA → error, get_published_crl_info, filter status `list_all`.

End-to-end flow đã chạy được (smoke):
1. Admin tạo Root CA
2. Customer Alice sinh keypair → submit CSR → admin approve → cert phát hành
3. **Alice yêu cầu thu hồi cert với reason "Key bị lộ"** → request pending
4. **Admin duyệt revoke request** → cert `revoked_at` set + status='approved'
5. **Admin bấm Publish CRL Now** → `certs/crl.pem` + `certs/ocsp_db.json` được ghi
6. CRL file ký bằng Root CA, parse + `is_signature_valid` OK; OCSP DB JSON chứa đúng serial

Tính năng đã dùng được:
- Admin: A.1-A.10 (đủ trừ A.11 đã có, tổng cộng 10 chức năng), Verification Lab.
- Customer: B.1-B.7 (đủ trừ B.8, B.9 — sẽ làm M9).

**Tổng test suite hiện tại:** 62/62 PASS (M1: 8, M4: 7, M5: 11, M6: 8, M7: 8, M8: 11, Legacy: 9).

### M9 — Customer view CRL + Upload external cert + Verify (đã làm)

- **`src/services/external_certs.py`** (B.9):
  - `parse_cert_summary(data)` — parse PEM hoặc DER, trả về subject/issuer/serial/validity/SAN/fingerprint cho preview.
  - `save_external_cert(uploader_id, data, notes, db_path)` — auto-convert DER → PEM trước khi lưu. Reject duplicate fingerprint per uploader (cross-user OK — Alice và Bob có thể cùng upload 1 cert).
  - `list_external_certs` / `get_external_cert` / `delete_external_cert` — BOLA-guard theo `uploader_id`.

- **`src/services/crl_publish.list_crl_entries(crl_path, db_path?)`** (B.8):
  - Parse file CRL hiện hành (load_pem_x509_crl) → list entries (serial, revocation_date).
  - Optional enrich từ DB: JOIN serial_hex với `issued_certs` + users để có `common_name` + `owner_username` hiển thị cho UX.

- **`src/ui/customer/view_crl_view.py`** (B.8) — header info CRL + filter (substring serial/CN) + bảng entries; chú thích rõ "Chưa có CRL được publish" nếu file thiếu.

- **`src/ui/customer/upload_external_view.py`** (B.9) — Notebook 2 tab:
  - "Upload": paste PEM hoặc browse file (.crt/.cer/.pem/.der) → Preview tự parse → nút "Upload + Lưu" với ghi chú tùy chọn.
  - "Của tôi": bảng list cert đã upload + nút Xem chi tiết (tái dùng `CertDetailDialog`) / Verify / Xóa.
  - `VerifyExternalDialog` — chạy `core.verify.verify_certificate_full` (5 bước) với Trust Store của hệ thống (auto-publish trước khi run), hiển thị log + banner PASS/FAIL.
    - Bước 1-3 hoạt động offline.
    - Bước 4 (CRL) + Bước 5 (OCSP) yêu cầu infra/crl_server + infra/ocsp_server đang chạy; nếu không thì 2 bước này fail với network error.

- **`tests/test_m9_external_crl.py`** — 8 test: parse PEM+DER fingerprint khớp manual, parse garbage raise, save happy + list enrich, duplicate per-uploader blocked + cross-uploader OK, BOLA (Bob không xem/xóa cert Alice), list_crl_entries với + không có db_path, file CRL thiếu → trả `[]`, DER input → PEM roundtrip OK.

End-to-end M9 đã chạy được (smoke):
1. Admin tạo Root CA + cấp 2 cert cho Alice + revoke 1 + publish CRL
2. Alice tab "Tra cứu CRL" → thấy 1 entry với CN + owner đã enrich
3. Alice upload cert ngoài (PEM/DER), preview thông tin, lưu vào DB
4. Alice mở dialog Verify → nhập hostname → 5 bước verify chạy với Trust Store hệ thống → banner PASS/FAIL

Tính năng đã dùng được:
- Admin: A.1-A.11 đủ + Verification Lab.
- Customer: B.1-B.9 đủ (register, login, đổi pw, keypair, CSR, xem/tải cert, yêu cầu thu hồi, **tra cứu CRL**, **upload + verify cert ngoài**).

**Tổng test suite hiện tại:** 70/70 PASS (M1: 8, M4: 7, M5: 11, M6: 8, M7: 8, M8: 11, **M9: 8**, Legacy: 9).

## Tổng kết tính năng đồ án MHUD đã hoàn thành

| Yêu cầu | Trạng thái |
|---|---|
| A.1 Admin đăng nhập | ✓ M3 |
| A.2 Admin đổi mật khẩu | ✓ M3 |
| A.3 Cấu hình kỹ thuật cấp phát | ✓ M4 |
| A.4 Sinh keypair Root CA | ✓ M4 |
| A.5 Sinh Root Certificate | ✓ M4 |
| A.6 Từ chối yêu cầu CSR | ✓ M6 |
| A.7 Phê duyệt + phát sinh cert | ✓ M6 |
| A.8 Quản lý cert (revoke + renew) | ✓ M7 |
| A.9 Duyệt yêu cầu thu hồi | ✓ M8 |
| A.10 Cập nhật CRL | ✓ M8 |
| A.11 Theo dõi nhật ký | ✓ M3 |
| B.1 Đăng ký tài khoản | ✓ M3 |
| B.2 Đăng nhập | ✓ M3 |
| B.3 Đổi mật khẩu | ✓ M3 |
| B.4 Sinh keypair cá nhân | ✓ M5 |
| B.5 Yêu cầu cấp cert (CSR) | ✓ M5 |
| B.6 Xem + tải cert | ✓ M7 |
| B.7 Yêu cầu thu hồi cert | ✓ M8 |
| B.8 Tra cứu CRL | ✓ M9 |
| B.9 Upload + verify cert ngoài | ✓ M9 |
| C. Encrypt-at-rest dữ liệu nhạy cảm | ✓ M1 + M4 + M5 |

Tất cả 20 yêu cầu chức năng (A.1-11 + B.1-9) + lưu ý C đều đã triển khai và có test cover.

### M10 — Polish + Submission (đã làm)

- **`src/ui/theme.py`** — Design system tập trung:
  - **Color tokens**: navy primary (`#1E3A8A`) + emerald accent + slate surface layers + status colors (success/warning/danger/info có cả tone đậm và soft bg).
  - **Font scale** (font preference chain, resolve runtime):
    - Heading: Clash Display → Hinato → Gudlak → Montserrat → Segoe UI
    - Body: Montserrat → Segoe UI → Arial
    - Mono: JetBrains Mono → Cascadia Code → Consolas
  - **Spacing scale** (4/8 rhythm): xxs=2, xs=4, sm=8, md=12, lg=16, xl=24, xxl=32.
  - **ttk Style** cho TFrame/Surface/Sidebar/Card + TLabel (Display/H1/H2/Muted/Subtle/Mono) + TButton (default/Primary/Accent/Danger/Ghost) + TEntry/TCombobox/TNotebook/Treeview/TScrollbar — tất cả wire vào `apply_theme(root)`.

- **`docs/DEMO_SCRIPT.md`** — Kịch bản video 15 phút end-to-end cho YouTube unlisted (Phần 0-8: intro, Admin first-run + Root CA, Customer onboarding, CSR workflow, cert download, revocation, CRL lookup + verify, security highlights, closing với test suite).

- **`docs/TECHNICAL_REPORT_OUTLINE.md`** — Sườn báo cáo Word 11 chương (giới thiệu, X.509+PKI, phân tích yêu cầu, thiết kế hệ thống, cài đặt, tính năng, bảo mật + QA, hướng dẫn sử dụng, kết quả, kết luận, phụ lục). Sẵn sàng copy/paste vào template trường.

- **`scripts/backup_db.py`** — Backup utility (D.2 yêu cầu nộp):
  - SQLite backup API → snapshot consistent của `ca_app.db` (kể cả khi app đang chạy).
  - Optional `--dump-sql` xuất plain SQL dump.
  - Copy `master.key` (có flag `--no-master-key` để omit nếu sợ leak), `certs/`, kèm `schema.sql`.
  - `backup_manifest.json` chứa SHA-256 + size + table counts để verify integrity.
  - In hướng dẫn restore từng bước.

- **README polish** — completion banner, tóm tắt admin/customer, link docs.

**Tổng test suite final:** 70/70 PASS (M1: 8, M4: 7, M5: 11, M6: 8, M7: 8, M8: 11, M9: 8, Legacy: 9).

## Cách chạy

```powershell
# Lần đầu
git clone <repo>
cd X509Certificate
pip install -r requirements.txt
python main.py
# → Console in: "Default admin created: admin / Admin@123. CHANGE IT after first login."

# Lần sau cứ chạy `python main.py`. DB + master.key + certs/ giữ nguyên từ session trước.

# Chạy toàn bộ test suite
$env:PYTHONIOENCODING='utf-8'
foreach ($t in @("test_m1_foundation","test_m4_ca_admin","test_m5_customer","test_m6_csr_admin","test_m7_cert_lifecycle","test_m8_revocation_crl","test_m9_external_crl","test_scenarios")) {
    python "tests/$t.py"
}

# Backup DB
python scripts/backup_db.py            # → backups/<timestamp>/
python scripts/backup_db.py --dump-sql # + plain SQL dump
python scripts/backup_db.py --no-master-key  # omit master.key cho an toàn khi nộp
```

## Tài liệu tham khảo

- [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) — kịch bản video YouTube
- [docs/TECHNICAL_REPORT_OUTLINE.md](docs/TECHNICAL_REPORT_OUTLINE.md) — sườn báo cáo Word
- [docs/DEMO_SCRIPT_LEGACY_LAB.md](docs/DEMO_SCRIPT_LEGACY_LAB.md) — kịch bản Verification Lab cũ (giữ làm tài liệu giảng bài 5-bước verify)

## Quy trình thao tác trên GUI

1. Bấm **Start CRL Server** để mở HTTP CRL server ở cổng `8889`.
2. Bấm **Start OCSP Server** để mở OCSP responder ở cổng `8888`.
3. Trong khung **Thêm Server mới**, nhập tên, port và chọn loại chứng chỉ.
4. Bấm **Thêm Server** để sinh cert (Root CA ký) và mở socket server tương ứng.
5. Chọn server trong bảng, bấm **Verify** để client nhận cert và chạy 5 bước xác thực.
6. Xem kết quả PASS/FAIL ở banner dưới cùng và log chi tiết bên phải.

Nút **Publish CRL Now** tạo lại `crl.pem` từ snapshot hiện tại của `ocsp_db.json`. Đây là điểm quan trọng để demo độ trễ của CRL so với OCSP.

## Các loại server demo

| Loại cert | Ý nghĩa | Kết quả mong đợi |
|-----------|---------|------------------|
| `valid` | Cert hợp lệ, do Root CA ký, chưa bị revoke. Reuse file trên disk nếu còn hợp lệ → pin warning của client ổn định qua các lần khởi động GUI | **PASS** tất cả 5 bước |
| `expired` | Cert đã hết hạn | **FAIL** ở Bước 2 |
| `revoked_both` | Serial đã có trong OCSP DB và CRL đã publish | **FAIL** ở Bước 4 và Bước 5 |
| `revoked_ocsp_only` | Serial chỉ có trong OCSP DB, CRL chưa publish | **FAIL** ở Bước 5, Bước 4 vẫn PASS cho đến khi publish CRL |
| `tampered` | Cert bị sửa 1 bit sau khi Root CA ký | **FAIL** ở Bước 1 |

## Mô hình trạng thái (lifecycle)

Mỗi `ServerEntry` có 3 trục **độc lập**:

| Trục | Giá trị | Ý nghĩa |
|------|---------|---------|
| `lifecycle` | `valid` / `expired` / `revoked` | Trạng thái pháp lý của cert |
| `revocation_scope` | `none` / `ocsp_only` / `both` | Mức lan truyền revocation (chỉ có ý nghĩa khi `lifecycle=revoked`) |
| `wire_mutation` | `none` / `tampered` | Mutation áp lên blob khi serve (độc lập với lifecycle) |

`flavor` (combobox lúc Thêm Server) là **state khởi tạo** (immutable, ghi nhận server "ban đầu là loại gì"). Các method state-transition trong `ServerManager` thay đổi các trục runtime mà KHÔNG sửa `flavor`.

**Lưu ý quan trọng**: `tampered` KHÔNG phải lifecycle state — đó là mutation trên đường truyền. Cert bị tamper KHÔNG tự động bị revoke: tampering là lỗi truyền tin (signature không khớp tbs, fail Bước 1), không phải lỗi key compromise. Bản cert "gốc" CA ký vẫn nằm yên trong records.

## Renew flow (lifecycle = expired/valid → valid)

Quy trình renew khi cert chuẩn bị hết hạn, theo best-practice:

1. **Trigger**: GUI bấm nút **🔄 Renew** trên server đang chọn (hoặc auto khi `mgr.is_renewal_due(name)` báo True).
2. **Rotate key + sinh cert mới**: `mgr.renew_server(name, rotate_key=True)` sinh keypair mới, dùng Root CA ký cert mới (validity_days mặc định 365), ghi đè file cert/key.
3. **Server hot-swap**: socket vẫn giữ; lần `GET_CERT` tiếp theo client nhận **cert mới**. Cert cũ không còn được serve.
4. **Client pin store overlap**:
   - Verify cert mới → Bước 1-5 PASS (cùng Root CA ký).
   - Bước phụ (pin): fingerprint mới không khớp pin cũ, nhưng cùng `issuer` → **ROTATION được chấp nhận tự động**, pin mới được THÊM vào (không xóa pin cũ).
   - Pin store `pin.json` v2 giờ chứa 2 entry — đây là "backup pin" trong cửa sổ overlap (giống HPKP backup pin).
5. **Cleanup**: khi cert cũ thực sự hết hạn (`not_valid_after < now`), pin cũ tự động bị prune ở lần verify kế tiếp; hoặc gọi thủ công `prune_expired_pins(hostname)`.

Để bị **reject** thay vì auto-accept, cert mới phải có issuer **khác** mọi pin đang giữ (đổi CA hoặc MITM bằng CA giả). Khi đó client trả FAIL ở bước phụ và yêu cầu xóa `pin.json` thủ công.

### Format pin.json v2

```json
{
  "version": 2,
  "hostname": "localhost",
  "pins": [
    {
      "fingerprint_sha256": "abc...",
      "subject": "CN=localhost,...",
      "issuer":  "CN=X509 Demo Root CA,...",
      "not_valid_before": "...",
      "not_valid_after":  "...",
      "first_seen": "...",
      "last_seen":  "..."
    }
  ]
}
```

File v1 (1 pin ở top-level) được tự động migrate sang v2 lần đọc đầu tiên — không cần xóa `pin.json` cũ.

## Kịch bản demo khuyến nghị

1. Tạo `Server-A`, port `9001`, loại `valid` → Verify: PASS (Root CA xác minh chữ ký OK).
2. Tạo `Server-B`, port `9002`, loại `expired` → Verify: FAIL ở thời hạn (Bước 1 vẫn PASS).
3. Tạo `Server-C`, port `9003`, loại `revoked_both` → Verify: CRL và OCSP đều báo revoked.
4. Tạo `Server-D`, port `9004`, loại `revoked_ocsp_only` → Verify: CRL chưa biết, OCSP báo revoked.
5. Bấm **Publish CRL Now**, verify lại `Server-D` → Bước 4 lúc này cũng FAIL.
6. Tắt checkbox **OCSP Responder ENABLED**, verify `Server-C` → CRL vẫn bắt được revoked, OCSP trả lỗi 503.
7. Tạo `Server-E`, port `9005`, loại `tampered` → Verify: chữ ký không verify được bằng Root CA.
8. **Renew flow**: chọn `Server-A` (valid), bấm **🔄 Renew** → log hiển thị `serial cũ → serial mới`; Verify lại → 5 bước vẫn PASS, log bước phụ báo "Pin ROTATION được chấp nhận" và pin store giờ có 2 fingerprint (cùng Root CA issuer).
9. Chọn một server và bấm **Xóa** để chứng minh port đóng và cert file bị xóa.

## Chi tiết 5 bước xác thực phía client

| Bước | Mục tiêu | Cách kiểm tra |
|------|----------|---------------|
| 1 | Verify chữ ký bằng Root CA | Load Root CA cert từ Trust Store, kiểm tra `server_cert.issuer == root_ca.subject`, dùng Root CA public key verify `tbs_certificate_bytes` |
| 2 | Thời hạn hiệu lực | So sánh `datetime.now(UTC)` với `not_valid_before` / `not_valid_after` |
| 3 | Hostname | Kiểm tra hostname nằm trong `SubjectAlternativeName` |
| 4 | CRL | Đọc `CRL Distribution Points`, tải `crl.pem` qua HTTP, verify chữ ký CRL bằng Root CA, sau đó check serial |
| 5 | OCSP | Đọc `Authority Information Access`, gọi `GET /ocsp?serial=...`, kiểm tra JSON `status` |

Sau 5 bước chính, client chạy thêm **bước phụ (advisory)** — KHÔNG ảnh hưởng PASS/FAIL tổng:

- **Lưu cert**: ghi PEM nhận được vào `received_certs/<hostname>/<timestamp>_<fp8>.pem` kèm `.json` metadata (`hostname`, `peer_address` = IP:port thực sự đã kết nối, `fingerprint_sha256`, `serial_number`, `subject`, `issuer`, …). Hữu ích cho audit: nếu thấy `hostname=foo.com` nhưng `peer_address` ngoài dải mong đợi → dấu hiệu DNS poisoning.
- **Pin warning (TOFU)**: lần đầu kết nối một hostname → lưu fingerprint vào `pin.json`; lần sau so sánh fingerprint mới với pin cũ. Mismatch → cảnh báo (cert có thể được rotate hợp lệ, hoặc đang bị MITM). Pin KHÔNG tự cập nhật khi mismatch — user phải xóa `pin.json` để chấp nhận cert mới.

Lưu ý:
- OCSP responder trong demo trả JSON `{"serial":"...","status":"GOOD"}` thay vì ASN.1 OCSP response chuẩn để dễ quan sát. Mục tiêu là mô phỏng logic kiểm tra trạng thái online, không triển khai đầy đủ chuẩn OCSP binary.
- Server cert mới được đặt `BasicConstraints(ca=False)` và `ExtendedKeyUsage = serverAuth` để giống vai trò TLS server cert thực tế (dù demo không chạy TLS thật).

## Giao thức giữa các thành phần

- **Client ↔ Socket server**
  - Client gửi: `b"GET_CERT"`
  - Server đáp: `[4 bytes length big-endian][PEM bytes của server cert]`

- **Client → OCSP**
  - `GET /ocsp?serial=<serial>` → `{"serial":"...","status":"GOOD"|"REVOKED"}`

- **Client → CRL**
  - `GET /crl.pem` → nội dung CRL PEM chuẩn X.509 (do Root CA ký)
