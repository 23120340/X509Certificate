# Demo Script - X.509 Dynamic Multi-Server (Root CA + Trust Store)

## Mục tiêu nói trong lúc mở demo

Demo này cho thấy client xác thực một chứng chỉ X.509 do **Root CA** ký qua 5 bước:

1. Verify chữ ký server cert bằng **Root CA public key trong Trust Store**.
2. Kiểm tra thời hạn hiệu lực.
3. Kiểm tra hostname trong SAN.
4. Verify chữ ký CRL bằng Root CA và kiểm tra serial trong CRL.
5. Hỏi OCSP responder để lấy trạng thái online.

Mô hình tin cậy:

```text
Root CA (self-signed)
    ├── ký Server Certificate
    └── ký CRL

Trust Store của client
    └── chứa Root CA certificate
```

Điểm nhấn chính: **CRL là snapshot**, còn **OCSP phản ánh trạng thái realtime hơn**. Client chỉ tin server cert nếu chữ ký verify được bằng Root CA trong Trust Store.

## Chuẩn bị

```bash
cd D:\repos\X509Certificate
python main.py
```

Trong GUI:

1. Bấm **Start CRL Server**.
2. Bấm **Start OCSP Server**.
3. Đảm bảo checkbox **OCSP Responder ENABLED** đang bật.

Khi GUI khởi động, Root CA tự được tạo ở `certs/issuer.crt` và publish vào `certs/trust_store/root_ca.crt`. Đây là Trust Store mà client sẽ load mỗi lần verify.

## Luồng demo chính

### 1. Cert hợp lệ

Tạo server:

- Tên: `Server-A`
- Port: `9001`
- Loại cert: `valid`

Bấm **Thêm Server**, chọn `Server-A`, bấm **Verify**.

Kết quả mong đợi: banner xanh **PASS**, cả 5 bước đều PASS. Log sẽ in dòng "Trust Store … chứa: CN=X509 Demo Root CA" trước khi chạy 5 bước.

Nói trong lúc demo: Bước 1 xác minh chữ ký server cert bằng Root CA — đúng theo mô hình PKI thực tế, không phải tự ký rồi tự verify.

### 2. Cert hết hạn

Tạo server:

- Tên: `Server-B`
- Port: `9002`
- Loại cert: `expired`

Verify `Server-B`.

Kết quả mong đợi: banner đỏ **FAIL**. Bước 1 vẫn PASS (Root CA ký đúng), Bước 2 fail vì `Not After` đã nằm trong quá khứ.

### 3. Cert bị thu hồi trong cả CRL và OCSP

Tạo server:

- Tên: `Server-C`
- Port: `9003`
- Loại cert: `revoked_both`

Verify `Server-C`.

Kết quả mong đợi: Bước 4 fail vì serial có trong CRL (CRL được Root CA ký nên client tin), Bước 5 fail vì OCSP trả `REVOKED`.

### 4. Điểm nhấn: OCSP biết trước CRL

Tạo server:

- Tên: `Server-D`
- Port: `9004`
- Loại cert: `revoked_ocsp_only`

Verify `Server-D`.

Kết quả mong đợi:

- Bước 4 CRL vẫn PASS vì CRL chưa được publish lại.
- Bước 5 OCSP FAIL vì OCSP DB đã có serial revoked.

Nói ngắn gọn: đây là lý do OCSP hữu ích khi cần trạng thái thu hồi gần realtime.

### 5. Publish CRL rồi verify lại

Bấm **Publish CRL Now**, sau đó verify lại `Server-D`.

Kết quả mong đợi: Bước 4 lúc này cũng FAIL vì CRL mới đã chứa serial của `Server-D`. Lưu ý: chữ ký CRL vẫn được Root CA ký, nên client vẫn tin nội dung CRL — chỉ là nội dung đã cập nhật.

### 6. OCSP down, CRL vẫn là fallback

Bỏ chọn checkbox **OCSP Responder ENABLED**, verify lại `Server-C`.

Kết quả mong đợi:

- Bước 4 CRL vẫn FAIL đúng vì cert đã bị revoke.
- Bước 5 OCSP FAIL do responder trả lỗi `503`.

Bật lại checkbox sau khi demo xong phần này.

### 7. Cert bị tamper

Tạo server:

- Tên: `Server-E`
- Port: `9005`
- Loại cert: `tampered`

Verify `Server-E`.

Kết quả mong đợi: Bước 1 fail vì chữ ký không còn verify được bằng Root CA sau khi cert bị sửa 1 bit — đây chính là lý do Trust Store + Root CA bảo vệ client khỏi cert bị giả mạo.

### 8. Xóa server

Chọn một server, bấm **Xóa**.

Ý nghĩa: demo phần quản lý vòng đời server, dừng port và xóa file cert/key tương ứng.

## Câu hỏi có thể gặp

> Vì sao không demo trang HTTPS thật?

Yêu cầu bài là mô phỏng mô hình X.509 (Root CA, Trust Store, CRL, OCSP), không phải triển khai TLS/HTTPS. Tách phần xác minh cert ra khỏi TLS để hiển thị rõ từng bước pass/fail, dễ quan sát hơn.

> OCSP trả JSON có chuẩn không?

Đây là phiên bản giản lược cho mục tiêu giáo dục — HTTP service trả `{"serial":"...","status":"GOOD"}`. OCSP chuẩn dùng ASN.1 binary response; logic kiểm tra trạng thái online vẫn giữ nguyên.

## Test nhanh trước khi trình bày

```powershell
$env:PYTHONIOENCODING='utf-8'
python test_scenarios.py
```

Kết quả mong đợi: `8 PASS / 0 FAIL`.
