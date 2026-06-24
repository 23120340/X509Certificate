# Hệ thống Quản lý và Cấp phát Chứng nhận X.509

Đồ án Mã hoá và Ứng dụng (MHUD): ứng dụng desktop quản lý Certificate Authority nội bộ, hỗ trợ phát hành, gia hạn, thu hồi và kiểm tra chứng chỉ X.509 v3 cho dịch vụ website theo luồng PKCS#10 CSR, CRL và OCSP.

> Trạng thái hiện tại: hoàn thành 20/20 yêu cầu chức năng A.1-A.11, B.1-B.9 và yêu cầu mã hoá dữ liệu nhạy cảm. Test hiện có: 81 test trong 9 file test, gồm 72 test chạy bằng pytest và 9 scenario chạy bằng runner riêng của Verification Lab.

## Tính năng chính

- Admin đăng nhập, đổi mật khẩu, cấu hình hệ thống (thuật toán khóa + hàm băm mặc định), tạo/rotate/publish Root CA với **RSA / ECDSA / Ed25519**, xem + export public key của Root CA.
- Admin duyệt/từ chối CSR, phát hành certificate, thu hồi, **gia hạn (renew tại chỗ — ký lại chính cert với thời hạn mới)**, **cấp lại toàn bộ cert dưới Root CA active**, duyệt yêu cầu thu hồi.
- Admin publish CRL từ snapshot DB (mỗi entry giữ đúng thời điểm thu hồi thực) và đồng bộ OCSP DB.
- Customer đăng ký, đăng nhập, đổi mật khẩu, tạo keypair **RSA / ECDSA / Ed25519**, tạo CSR, xem chi tiết/tải certificate.
- Customer gửi yêu cầu thu hồi, tra cứu CRL, upload certificate ngoài và chạy verify 5 bước.
- LAN CSR mode: máy Admin bật CSR API, máy Customer gửi CSR/cập nhật danh sách cert/yêu cầu thu hồi qua LAN; private key vẫn nằm ở máy Customer.
- Prod CRL/OCSP server tự khởi động cùng app; Verification Lab dùng cặp Lab CRL/OCSP riêng.
- Audit log đầy đủ cho **mọi hành vi thay đổi trạng thái** của user (tạo/sửa/xóa/ký/thu hồi/publish…).
- Mọi mốc thời gian hiển thị theo **giờ local kèm nhãn múi giờ** (lưu trữ vẫn là UTC ISO-8601).
- Private key được mã hoá AES-256-GCM; password hash bằng scrypt; service customer có BOLA/ownership guard.

## Thuật toán khóa, hàm băm và vòng đời chứng chỉ

### Thuật toán hỗ trợ
- **RSA**: 2048 / 3072 / 4096 bit.
- **ECDSA**: đường cong P-256 (secp256r1) / P-384 (secp384r1).
- **Ed25519**: EdDSA (hàm băm SHA-512 cố định bên trong).

Áp dụng cho keypair khách hàng, CSR và Root CA. Nguồn sự thật chung: `src/core/keyalg.py`.

### Bộ chọn khóa cascading (dùng chung)
Widget `src/ui/widgets/keyalg_selector.py` được **dùng chung** cho cả tab *Cấu hình hệ thống* và dialog *Sinh Root CA mới* nên hai nơi luôn đồng bộ:

`Loại khóa → key size (RSA) / đường cong (ECDSA) / (Ed25519 không cần) → hàm băm phù hợp`

Mặc định ở *Cấu hình hệ thống* (`default_key_algorithm` + `default_key_size`/`default_ec_curve` + `hash_algorithm`) sẽ tự prefill vào dialog Sinh Root CA.

### Ràng buộc khóa ↔ hàm băm
Hàm băm chữ ký lấy từ `system_config.hash_algorithm`. Ràng buộc theo loại khóa được áp dụng ở **cả UI lẫn backend** (`keyalg.signing_algorithm`):
- **RSA** — dùng được mọi SHA-256/384/512.
- **ECDSA** — hàm băm phải ≥ độ mạnh đường cong (NIST SP 800-57 / RFC 5480): P-256 → SHA-256/384/512; **P-384 → SHA-384/512** (loại SHA-256). Backend tự "ép lên" mức tối thiểu khi cấu hình toàn cục yếu hơn (vd Root CA EC-P384 ký cert con/CRL bằng `hash_algorithm=SHA-256` sẽ được ký bằng SHA-384).
- **Ed25519** — hàm băm cố định, không chọn; ký với `algorithm=None`.

### Vòng đời chứng chỉ
- **Renew (gia hạn) = ký lại TẠI CHỖ**: cập nhật chính record trong `issued_certs` (giữ id, subject, public key, extensions), thời hạn mới, serial mới (X.509 yêu cầu serial duy nhất per issuer) — KHÔNG tạo thêm cert mới.
- **Cấp lại toàn bộ (re-issue all)** khi đổi/active Root CA: ký lại mọi cert còn hiệu lực dưới Root CA active, thu hồi bản cũ với lý do `superseded` và publish CRL mới; idempotent (bỏ qua cert đã do CA active ký, cert đã revoke/hết hạn).
- **CRL**: mỗi entry giữ đúng `revoked_at` thực của cert (đọc từ DB), không bị đặt lại theo thời điểm publish.

### Xem chi tiết chứng chỉ
Decode đầy đủ: version, serial (hex theo cặp byte), thuật toán chữ ký, issuer/subject DN tách thành phần, validity (giờ local), **public key value + fingerprint SHA-256/SHA-1**, và toàn bộ extension v3 (BasicConstraints, KeyUsage, EKU, SAN, SKI, AKI, CRLDP, AIA…).

## Công nghệ

- Python 3
- Tkinter/ttk
- SQLite
- `cryptography`
- HTTP server từ Python standard library cho CRL, OCSP và CSR API

## Cấu trúc project

```text
X509Certificate/
|-- main.py
|-- requirements.txt
|-- README.md
|-- docs/
|   |-- DEMO_SCRIPT.md
|   |-- DEMO_SCRIPT_LEGACY_LAB.md
|   |-- TECHNICAL_REPORT_OUTLINE.md
|   `-- *.pptx, assets/
|-- lab/
|   |-- issuer.crt
|   |-- issuer.key
|   |-- Server-A.crt
|   |-- Server-A.key
|   |-- crl.pem
|   |-- ocsp_db.json
|   `-- trust_store/
|-- scripts/
|   |-- backup_db.py
|   |-- dump_cert.py
|   `-- submit_csr_lan.py
|-- src/
|   |-- config.py
|   |-- core/
|   |-- db/
|   |-- infra/
|   |-- legacy/
|   |-- services/
|   `-- ui/
`-- tests/
    |-- test_infra_manager.py
    |-- test_m1_foundation.py
    |-- test_m4_ca_admin.py
    |-- test_m5_customer.py
    |-- test_m6_csr_admin.py
    |-- test_m7_cert_lifecycle.py
    |-- test_m8_revocation_crl.py
    |-- test_m9_external_crl.py
    `-- test_scenarios.py
```

Các file/thư mục runtime như `ca_app.db`, `master.key`, `certs/`, `client_artifacts/`, `backups/` và `.pytest_cache/` được sinh khi chạy app/test/script, không phải source chính.

## Module quan trọng

- `src/core/`: primitive X.509 và crypto: CA, CSR, certificate builder, CRL, verify, encryption.
- `src/db/`: SQLite schema và connection helper.
- `src/services/`: business logic cho auth, audit, system config, Root CA, CSR, lifecycle cert, revocation, CRL publish, external cert, LAN CSR.
- `src/infra/`: CRL HTTP server, OCSP responder và CSR API server.
- `src/ui/`: giao diện Tkinter cho login, admin dashboard và customer dashboard.
- `src/legacy/`: Verification Lab demo valid/expired/revoked/tampered/renew.
- `scripts/`: tiện ích backup DB, dump cert từ DB và submit CSR qua LAN.

## Cài đặt

```powershell
cd D:\repos\X509Certificate
pip install -r requirements.txt
```

Để chạy test, cài thêm pytest:

```powershell
pip install pytest
```

## Chạy ứng dụng

```powershell
cd D:\repos\X509Certificate
python main.py
```

Lần chạy đầu tiên app sẽ:

- Tạo `ca_app.db`.
- Tạo `master.key` 32 bytes dùng cho AES-GCM.
- Seed `system_config`.
- Seed admin mặc định nếu DB chưa có admin.
- Tạo/chẩn bị `certs/` cho Prod CRL, OCSP DB và trust store.
- Tự động start Prod CRL server tại `http://localhost:8889/crl.pem`.
- Tự động start Prod OCSP responder tại `http://localhost:8888/ocsp`.

Tài khoản admin mặc định:

```text
Username: admin
Password: Admin@123
```

Nên đổi mật khẩu admin sau lần đăng nhập đầu tiên.

## Chạy test

Các test workflow/module chạy bằng pytest:

```powershell
cd D:\repos\X509Certificate
python -m pytest --ignore=tests/test_scenarios.py
```

`tests/test_scenarios.py` có runner riêng vì cần gọi `setup()`/`teardown()` cho Lab CRL/OCSP server và các socket demo theo thứ tự:

```powershell
$env:PYTHONIOENCODING="utf-8"
python tests\test_scenarios.py
```

Có thể chạy toàn bộ theo cách tuần tự:

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest --ignore=tests/test_scenarios.py
python tests\test_scenarios.py
```

Một số test infra/scenario có bind port local. Nếu port đang bị chiếm, hãy đóng app khác hoặc đổi port bằng biến môi trường.

## LAN CSR mode

Mô hình demo LAN:

```text
Máy Admin/CA
  Chạy CA app, bật CSR API, nhận CSR từ client, approve/reject trong CSR Queue.

Máy Customer
  Sinh keypair và CSR cục bộ, gửi CSR qua LAN tới Admin API.
  Private key không rời khỏi máy Customer.
```

Trên máy Admin:

1. Chạy `python main.py`.
2. Ở màn hình login, chọn chế độ máy Admin nhận CSR.
3. Nhập bind host/port, ví dụ `0.0.0.0:8787`.
4. Nhập token rồi bấm **Bật CSR API**.
5. Đăng nhập admin và mở **Duyệt CSR**.

Khi bind ra LAN/public, token là bắt buộc. Có thể đặt trước bằng biến môi trường:

```powershell
$env:X509_CSR_API_HOST="0.0.0.0"
$env:X509_CSR_API_PORT="8787"
$env:X509_CSR_API_TOKEN="demo-secret"
python main.py
```

Trên máy Customer:

1. Chạy `python main.py`.
2. Ở màn hình login, chọn chế độ máy Client gửi CSR.
3. Nhập URL Admin API, ví dụ `http://192.168.1.10:8787`, và token.
4. Đăng ký/đăng nhập customer, sinh keypair, rồi submit CSR.

Có thể test nhanh bằng script:

```powershell
python scripts\submit_csr_lan.py `
  --server http://192.168.1.10:8787 `
  --username alice `
  --password AlicePw123 `
  --domain myshop.com `
  --san myshop.com,www.myshop.com `
  --key-name alice-lan-key `
  --token demo-secret
```

Script sẽ sinh private key và CSR trong `client_artifacts/`, sau đó gửi CSR tới `POST /api/csr/submit`.

Các endpoint CSR API chính:

- `GET /health`
- `POST /api/csr/submit`
- `POST /api/customer/csrs`
- `POST /api/customer/csr/detail`
- `POST /api/customer/certs`
- `POST /api/customer/cert/detail`
- `POST /api/customer/revoke/submit`
- `POST /api/customer/revoke/requests`
- `POST /api/crl/current`

## CRL, OCSP và Verification Lab

- Prod CRL/OCSP dùng `certs/crl.pem` và `certs/ocsp_db.json`, tự start cùng app ở port `8889/8888`.
- Verification Lab dùng dữ liệu trong `lab/`, start thủ công khi mở Lab, mặc định ở port `9889/9888`.
- Cert phát hành bởi app nhúng CRL Distribution Point và AIA OCSP theo URL Prod hiện tại.
- Có thể override port:

```powershell
$env:PROD_CRL_PORT="8889"
$env:PROD_OCSP_PORT="8888"
$env:LAB_CRL_PORT="9889"
$env:LAB_OCSP_PORT="9888"
```

Verification Lab dùng để minh hoạ:

- `valid`: pass 5 bước.
- `expired`: fail ở bước thời hạn.
- `revoked_both`: fail ở CRL và OCSP.
- `revoked_ocsp_only`: OCSP biết trước CRL.
- `tampered`: fail vì chữ ký không khớp.
- Renew: cert mới (khác serial) do cùng Root CA ký vẫn pass đủ 5 bước.

## Script hỗ trợ

```powershell
python scripts\backup_db.py
python scripts\backup_db.py --dump-sql
python scripts\backup_db.py --no-master-key
```

`backup_db.py` backup `ca_app.db`, `master.key`, `certs/`, schema và manifest SHA-256 vào `backups/<timestamp>/`.

```powershell
python scripts\dump_cert.py
python scripts\dump_cert.py <cert_id>
python scripts\dump_cert.py <cert_id> <output.pem>
```

`dump_cert.py` liệt kê hoặc xuất certificate đã cấp từ database.

```powershell
python scripts\submit_csr_lan.py --server http://<admin-ip>:8787 --username alice --password AlicePw123 --domain example.com --token demo-secret
```

`submit_csr_lan.py` tạo keypair/CSR cục bộ và gửi CSR qua LAN tới Admin API.

## Ghi chú bảo mật và vận hành

- `master.key` và `ca_app.db` phải đi theo cặp; mismatch sẽ không giải mã được private key đã lưu.
- Không commit hoặc nộp kèm `master.key`, `ca_app.db`, `certs/`, `client_artifacts/`, `received_certs/`, `backups/`.
- CSR LAN chỉ gửi public CSR; private key của customer vẫn ở máy client.
- OCSP responder trong demo trả JSON để dễ quan sát, không phải OCSP ASN.1 binary chuẩn.
- SQLite phù hợp đồ án/demo offline; production thực tế nên dùng HSM/KMS cho key, DB server, backup policy và OCSP chuẩn.

