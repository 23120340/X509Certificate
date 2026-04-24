# Hệ thống mô phỏng xác thực chứng chỉ X.509 v3 (Self-signed)

Bài tập mô phỏng quá trình một HTTPS client xác thực chứng chỉ X.509 v3 tự ký, bao gồm đầy đủ các bước: verify chữ ký, kiểm tra thời hạn, kiểm tra hostname (SAN), kiểm tra CRL, và gọi OCSP.

## Cấu trúc project

```
x509_sim/
├── cert_generator.py   # Phần 1: Sinh key + tạo cert X.509 v3 self-signed
├── server.py           # Phần 2: Socket server gửi cert cho client
├── client.py           # Phần 3: Client thực hiện 5 bước xác thực
├── crl_manager.py      # Phần 4: Tạo CRL
├── crl_server.py       # HTTP server phát file CRL
├── ocsp_server.py      # Phần 5: HTTP OCSP service (GOOD/REVOKED)
├── gui.py              # Phần 6: Tkinter GUI
├── main.py             # Điểm vào
├── requirements.txt
└── certs/              # Được tự tạo khi chạy
    ├── server.crt
    ├── server.key
    ├── crl.pem
    └── revoked_serials.json
```

## Cài đặt

```bash
pip install -r requirements.txt
```

(Tkinter có sẵn trong Python standard library trên hầu hết các bản cài đặt.)

## Chạy chương trình

```bash
python main.py
```

## Quy trình thao tác trên GUI

Theo thứ tự các nút đánh số:

1. **Chọn kịch bản** ở bên trái (Valid / Expired / Revoked).
2. **① Generate Certificate** – sinh cặp khóa RSA + cert X.509 v3 + CRL tương ứng.
3. **② Start CRL Server** – mở HTTP server phát `crl.pem` (cổng 8889).
4. **③ Start OCSP Server** – mở HTTP OCSP service (cổng 8888).
5. **④ Start Server** – mở Socket server phát certificate (cổng 9999).
6. **⑤ Connect Client & Verify** – Client kết nối, nhận cert, chạy 5 bước xác thực.

Kết quả PASS/FAIL hiện ở thanh banner dưới cùng (xanh / đỏ).

## 3 kịch bản kiểm thử

| STT | Kịch bản                     | Cách test                            | Kết quả mong đợi |
|-----|------------------------------|--------------------------------------|------------------|
| 1   | Chứng chỉ hợp lệ             | Chọn "Valid", bấm ①→⑤                | **PASS** (xanh)  |
| 2   | Chứng chỉ hết hạn            | Chọn "Expired", bấm ①→⑤              | **FAIL** (đỏ)   – Bước 2 fail |
| 3   | Chứng chỉ bị thu hồi         | Chọn "Revoked", bấm ①→⑤              | **FAIL** (đỏ)   – Bước 4 & 5 fail |

## Chi tiết các bước xác thực (phía Client)

| Bước | Mục tiêu               | Cách kiểm tra |
|------|------------------------|---------------|
| 1    | Verify chữ ký số       | Dùng public key trong chính cert (vì là self-signed) để verify signature trên `tbs_certificate_bytes` |
| 2    | Thời hạn hiệu lực      | So sánh `datetime.now(UTC)` với `not_valid_before` / `not_valid_after` |
| 3    | Hostname               | Kiểm tra hostname nằm trong `SubjectAlternativeName` (DNSName hoặc IPAddress) |
| 4    | CRL                    | Đọc `CRL Distribution Points` extension → tải file CRL từ HTTP → check serial |
| 5    | OCSP                   | Đọc `Authority Information Access` extension → gọi `GET /ocsp?serial=...` → kiểm tra JSON `status` |

## Giao thức giữa các thành phần

- **Client ↔ Server (Socket)** – cổng 9999
  - Client gửi: `b"GET_CERT"`
  - Server đáp: `[4 bytes length big-endian][PEM bytes]`

- **Client → OCSP (HTTP)** – cổng 8888
  - `GET /ocsp?serial=<serial>` → `{"serial":"...","status":"GOOD"|"REVOKED"}`

- **Client → CRL (HTTP)** – cổng 8889
  - `GET /crl.pem` → nội dung CRL PEM chuẩn X.509
