# Review demo X.509

## Kết luận ngắn

Demo hiện tại **phù hợp nếu mục tiêu là mô phỏng các bước kiểm tra X.509**: chữ ký, thời hạn, hostname, CRL và OCSP. Các kịch bản `valid`, `expired`, `revoked_both`, `revoked_ocsp_only`, `tampered` đều có giá trị trình bày rõ ràng.

Tuy nhiên, nếu đề bài nêu mô hình có **Root CA** và **Trust Store** nhưng bỏ qua chain trung gian, thì demo hiện tại cần cải thiện một điểm quan trọng: server certificate không nên tự ký bằng chính key của nó nữa. Nên chuyển sang mô hình:

```text
Root CA self-signed
    |
    +-- ký Server Certificate

Client Trust Store
    |
    +-- chứa Root CA certificate
```

Client sau đó verify chữ ký server cert bằng public key của Root CA trong Trust Store. Như vậy vẫn bỏ qua Chain of Trust trung gian, nhưng vẫn đúng ý tưởng Root CA và Trust Store.

## Phần hiện tại đã ổn

### 1. Luồng demo dễ hiểu

GUI Dynamic Multi-Server phù hợp để trình bày vì mỗi server đại diện cho một trạng thái chứng chỉ:

| Flavor | Ý nghĩa | Kết quả demo |
|--------|---------|--------------|
| `valid` | Cert hợp lệ | PASS cả 5 bước |
| `expired` | Cert hết hạn | FAIL ở bước thời hạn |
| `revoked_both` | OCSP và CRL đều biết cert bị thu hồi | FAIL ở CRL và OCSP |
| `revoked_ocsp_only` | OCSP biết trước, CRL chưa publish | CRL PASS, OCSP FAIL |
| `tampered` | Cert bị sửa sau khi ký | FAIL chữ ký |

Đây là cách demo tốt vì người xem thấy từng lỗi cụ thể thay vì chỉ thấy một kết quả chung chung.

### 2. Điểm nhấn CRL vs OCSP tốt

Case `revoked_ocsp_only` rất đáng giữ. Nó giải thích được khác biệt quan trọng:

- CRL là danh sách được publish theo thời điểm.
- OCSP phản hồi trạng thái online hơn.
- Sau khi bấm **Publish CRL Now**, CRL mới bắt được serial bị thu hồi.

Đây là phần có tính thuyết phục cao trong demo.

### 3. Test end-to-end đã bao phủ đúng các kịch bản

`test_scenarios.py` đã kiểm tra đủ các hành vi quan trọng:

- cert hợp lệ
- cert hết hạn
- revoke bằng CRL + OCSP
- OCSP biết trước CRL
- publish CRL
- OCSP down
- cert bị tamper
- xóa server

Trước khi demo nên chạy:

```powershell
$env:PYTHONIOENCODING='utf-8'
python test_scenarios.py
```

Kết quả mong đợi: `8 PASS / 0 FAIL`.

## Điểm cần cải thiện để khớp đề bài hơn

### 1. Server cert hiện đang self-signed

Hiện tại `cert_generator.py` tạo server cert theo mô hình:

```text
issuer == subject
server private key ký chính server certificate
```

Điều này phù hợp với demo self-signed, nhưng chưa thể hiện đúng mô hình Root CA + Trust Store.

Nên đổi sang:

```text
issuer = Root CA subject
subject = localhost/server name
Root CA private key ký server certificate
```

Khi đó client verify chữ ký bằng Root CA public key lấy từ Trust Store.

### 2. Root CA hiện mới dùng để ký CRL

`issuer.py` đã có CA nội bộ, nhưng vai trò hiện tại chủ yếu là ký CRL. Nên nâng vai trò này thành **Root CA thật trong mô hình demo**:

- Root CA là self-signed.
- Root CA nằm trong Trust Store.
- Root CA ký server cert.
- Root CA ký CRL.

Như vậy mô hình nhất quán hơn nhiều.

### 3. Trust Store chưa được mô phỏng rõ

Hiện client chưa có bước đọc Trust Store. Nên thêm một file hoặc thư mục:

```text
certs/trust_store/
└── root_ca.crt
```

Hoặc đơn giản hơn:

```text
certs/ca.crt
```

Trong demo có thể nói:

> Trust Store của client chứa Root CA certificate. Client chỉ tin server certificate nếu chữ ký của server cert verify được bằng Root CA public key trong Trust Store.

### 4. Bước 1 nên đổi tên và đổi logic

Hiện Bước 1 là:

```text
Verify chữ ký self-signed bằng public key trong chính cert
```

Nên đổi thành:

```text
Bước 1 - Verify chữ ký bằng Root CA trong Trust Store
```

Logic mong muốn:

1. Load server cert.
2. Load Root CA cert từ Trust Store.
3. Kiểm tra `server_cert.issuer == root_ca_cert.subject`.
4. Dùng public key của Root CA verify chữ ký server cert.
5. Nếu verify fail thì cert không đáng tin hoặc bị tamper.

Điểm này là cải thiện quan trọng nhất.

### 5. Server cert không nên có `BasicConstraints(ca=True)`

Server certificate hiện đang có `BasicConstraints(ca=True)`. Nếu server cert được Root CA ký, nên đổi thành:

```text
BasicConstraints(ca=False)
```

Và nên thêm Extended Key Usage:

```text
serverAuth
```

Điều này làm certificate giống server certificate thật hơn, dù demo không cần chạy HTTPS thật.

### 6. CRL nên được ký bởi cùng Root CA đã ký server cert

Khi server cert được ký bởi Root CA, CRL cũng nên do Root CA ký. Lúc client tải CRL, có thể kiểm tra thêm:

1. CRL issuer khớp Root CA subject.
2. CRL signature verify được bằng Root CA public key.
3. Serial của server cert có nằm trong CRL không.

Hiện demo chỉ check serial trong CRL. Nếu thêm verify chữ ký CRL, demo sẽ chắc hơn.

### 7. OCSP demo hiện là mô phỏng đơn giản, nên nói rõ

OCSP server hiện trả JSON:

```json
{"serial": "...", "status": "GOOD"}
```

Đây là mô phỏng hợp lý cho bài demo, nhưng không phải OCSP ASN.1 response chuẩn. Khi trình bày nên nói:

> OCSP ở đây được giản lược thành HTTP JSON service để dễ quan sát trạng thái GOOD/REVOKED. Mục tiêu là mô phỏng logic kiểm tra trạng thái online, không triển khai đầy đủ chuẩn OCSP binary.

## Có cần demo HTTP lên HTTPS không?

Không cần, nếu đề bài chỉ yêu cầu mô hình X.509.

Nên tránh tự mở rộng sang demo HTTPS thật vì sẽ làm bài phức tạp hơn:

- cần TLS handshake
- cần server cert đúng chuẩn hơn
- cần trust CA trong browser hoặc trong HTTP client
- CRL/OCSP trong TLS thật phức tạp hơn nhiều và nhiều client không tự check revocation theo cách dễ demo

Cách nói hợp lý khi demo:

> Demo này tách riêng phần xác thực certificate X.509 để quan sát từng bước. Trong HTTPS thật, certificate cũng được server gửi trong TLS handshake, nhưng bài này tập trung vào mô hình certificate, Root CA, Trust Store, CRL và OCSP.

Nếu giảng viên hỏi vì sao không có trang `https://localhost`, có thể trả lời:

> Vì yêu cầu bài là mô phỏng X.509, không phải triển khai TLS/HTTPS. Phần xác minh cert đang được tách ra khỏi TLS để hiển thị rõ từng bước pass/fail.

## Kịch bản demo khuyến nghị sau khi cải thiện Root CA + Trust Store

### Bước mở đầu

Giới thiệu mô hình:

```text
Root CA certificate nằm trong Trust Store của client.
Root CA private key ký server certificate.
Server gửi certificate cho client.
Client dùng Root CA trong Trust Store để verify chữ ký.
```

### Demo 1: Valid certificate

Tạo `Server-A` loại `valid`.

Kỳ vọng:

- Bước 1: chữ ký server cert verify được bằng Root CA.
- Bước 2: cert còn hạn.
- Bước 3: hostname khớp SAN.
- Bước 4: serial không có trong CRL.
- Bước 5: OCSP trả GOOD.

Kết quả: PASS.

### Demo 2: Expired certificate

Tạo `Server-B` loại `expired`.

Kỳ vọng:

- Bước 1 vẫn PASS vì chữ ký đúng.
- Bước 2 FAIL vì cert hết hạn.

Kết quả: FAIL có lý do rõ.

### Demo 3: Revoked by CRL and OCSP

Tạo `Server-C` loại `revoked_both`.

Kỳ vọng:

- Bước 4 FAIL vì serial có trong CRL.
- Bước 5 FAIL vì OCSP trả REVOKED.

Kết quả: FAIL.

### Demo 4: OCSP biết trước CRL

Tạo `Server-D` loại `revoked_ocsp_only`.

Kỳ vọng lần verify đầu:

- Bước 4 PASS vì CRL chưa publish.
- Bước 5 FAIL vì OCSP đã biết revoked.

Sau đó bấm **Publish CRL Now** và verify lại:

- Bước 4 cũng FAIL.

Đây là phần nên nhấn mạnh nhất.

### Demo 5: Tampered certificate

Tạo `Server-E` loại `tampered`.

Kỳ vọng:

- Bước 1 FAIL vì chữ ký không verify được bằng Root CA.

Kết quả: FAIL ngay từ bước đầu.

## Thứ tự ưu tiên sửa code

### Ưu tiên 1: Đổi server cert sang Root CA-signed

Việc cần làm:

- Đổi `create_self_signed_cert` thành hoặc thêm hàm mới `create_server_cert_signed_by_ca`.
- Truyền vào `issuer_cert` và `issuer_key`.
- Set `issuer_name(issuer_cert.subject)`.
- Sign bằng `issuer_key`.
- Server cert dùng `BasicConstraints(ca=False)`.

### Ưu tiên 2: Thêm Trust Store vào client

Việc cần làm:

- Thêm tham số `trust_store_path` hoặc `root_ca_cert_path`.
- Load Root CA cert.
- Bước 1 verify server cert bằng Root CA public key.
- Log rõ Root CA subject và server cert issuer.

### Ưu tiên 3: Verify CRL signature

Việc cần làm:

- Sau khi tải CRL, kiểm tra CRL issuer.
- Verify chữ ký CRL bằng Root CA public key.
- Sau đó mới check serial.

### Ưu tiên 4: Cập nhật README và DEMO_SCRIPT

Việc cần làm:

- Đổi mô tả từ self-signed server cert sang Root CA-signed server cert.
- Giải thích Trust Store.
- Giữ nguyên kịch bản Dynamic Multi-Server.

## Tổng kết

Không cần demo một trang HTTP lên HTTPS nếu đề bài chỉ yêu cầu mô hình X.509. Demo hiện tại đã có nền tốt, nhưng để khớp chính xác với yêu cầu **Root CA + Trust Store**, nên sửa trọng tâm ở Bước 1:

```text
Từ: server cert tự ký, verify bằng public key trong chính cert
Sang: server cert do Root CA ký, verify bằng Root CA certificate trong Trust Store
```

Sau thay đổi này, bài demo sẽ vừa đúng scope đề bài, vừa tránh bị bắt bẻ rằng chưa có cơ chế trust thật.
