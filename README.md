# Hệ thống mô phỏng xác thực chứng chỉ X.509 v3 (Root CA + Trust Store)

Bài tập mô phỏng quá trình một client xác thực chứng chỉ X.509 v3 do **Root CA** ký, bao gồm 5 bước: verify chữ ký bằng Root CA trong Trust Store, kiểm tra thời hạn, kiểm tra hostname (SAN), kiểm tra CRL và gọi OCSP.

Phiên bản hiện tại là demo **Dynamic Multi-Server**: có thể tạo nhiều socket server cùng lúc, mỗi server dùng một loại chứng chỉ khác nhau để đối chiếu kết quả PASS/FAIL.

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
├── cert_generator.py   # Sinh key; tạo server cert do Root CA ký
├── issuer.py           # Root CA (self-signed) + Trust Store helper
├── client.py           # Client thực hiện 5 bước xác thực
├── crl_manager.py      # Quản lý OCSP DB và publish CRL (Root CA ký)
├── crl_server.py       # HTTP server phát file CRL
├── ocsp_server.py      # HTTP OCSP service (GOOD/REVOKED hoặc 503 khi tắt)
├── server_manager.py   # Quản lý nhiều socket server demo
├── gui.py              # Tkinter GUI
├── main.py             # Điểm vào
├── test_scenarios.py   # Test end-to-end cho các kịch bản demo
├── requirements.txt
└── certs/              # Được tự tạo khi chạy
    ├── issuer.crt          # Root CA cert (issuer)
    ├── issuer.key          # Root CA private key
    ├── crl.pem             # CRL do Root CA ký
    ├── ocsp_db.json        # Realtime revocation DB của OCSP responder
    └── trust_store/
        └── root_ca.crt     # Bản sao Root CA — client đọc khi verify
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

Nếu console Windows bị lỗi in tiếng Việt khi chạy test, dùng:

```powershell
$env:PYTHONIOENCODING='utf-8'
python test_scenarios.py
```

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
| `valid` | Cert hợp lệ, do Root CA ký, chưa bị revoke | **PASS** tất cả 5 bước |
| `expired` | Cert đã hết hạn | **FAIL** ở Bước 2 |
| `revoked_both` | Serial đã có trong OCSP DB và CRL đã publish | **FAIL** ở Bước 4 và Bước 5 |
| `revoked_ocsp_only` | Serial chỉ có trong OCSP DB, CRL chưa publish | **FAIL** ở Bước 5, Bước 4 vẫn PASS cho đến khi publish CRL |
| `tampered` | Cert bị sửa 1 bit sau khi Root CA ký | **FAIL** ở Bước 1 |

## Kịch bản demo khuyến nghị

1. Tạo `Server-A`, port `9001`, loại `valid` → Verify: PASS (Root CA xác minh chữ ký OK).
2. Tạo `Server-B`, port `9002`, loại `expired` → Verify: FAIL ở thời hạn (Bước 1 vẫn PASS).
3. Tạo `Server-C`, port `9003`, loại `revoked_both` → Verify: CRL và OCSP đều báo revoked.
4. Tạo `Server-D`, port `9004`, loại `revoked_ocsp_only` → Verify: CRL chưa biết, OCSP báo revoked.
5. Bấm **Publish CRL Now**, verify lại `Server-D` → Bước 4 lúc này cũng FAIL.
6. Tắt checkbox **OCSP Responder ENABLED**, verify `Server-C` → CRL vẫn bắt được revoked, OCSP trả lỗi 503.
7. Tạo `Server-E`, port `9005`, loại `tampered` → Verify: chữ ký không verify được bằng Root CA.
8. Chọn một server và bấm **Xóa** để chứng minh port đóng và cert file bị xóa.

## Chi tiết 5 bước xác thực phía client

| Bước | Mục tiêu | Cách kiểm tra |
|------|----------|---------------|
| 1 | Verify chữ ký bằng Root CA | Load Root CA cert từ Trust Store, kiểm tra `server_cert.issuer == root_ca.subject`, dùng Root CA public key verify `tbs_certificate_bytes` |
| 2 | Thời hạn hiệu lực | So sánh `datetime.now(UTC)` với `not_valid_before` / `not_valid_after` |
| 3 | Hostname | Kiểm tra hostname nằm trong `SubjectAlternativeName` |
| 4 | CRL | Đọc `CRL Distribution Points`, tải `crl.pem` qua HTTP, verify chữ ký CRL bằng Root CA, sau đó check serial |
| 5 | OCSP | Đọc `Authority Information Access`, gọi `GET /ocsp?serial=...`, kiểm tra JSON `status` |

Lưu ý:
- OCSP responder trong demo trả về JSON dạng `{"serial":"...","status":"GOOD"}` thay vì ASN.1 OCSP response chuẩn để dễ quan sát. Mục tiêu là mô phỏng logic kiểm tra trạng thái online, không triển khai đầy đủ chuẩn OCSP binary.
- Server cert mới được đặt `BasicConstraints(ca=False)` và `ExtendedKeyUsage = serverAuth` để giống vai trò TLS server cert thực tế (dù demo không chạy TLS thật).

## Giao thức giữa các thành phần

- **Client ↔ Socket server**
  - Client gửi: `b"GET_CERT"`
  - Server đáp: `[4 bytes length big-endian][PEM bytes của server cert]`

- **Client → OCSP**
  - `GET /ocsp?serial=<serial>` → `{"serial":"...","status":"GOOD"|"REVOKED"}`

- **Client → CRL**
  - `GET /crl.pem` → nội dung CRL PEM chuẩn X.509 (do Root CA ký)
