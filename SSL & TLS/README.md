# SSL/TLS: hành trình thông điệp A → B

Ứng dụng cục bộ cho bài tập mật mã: chọn phiên bản và thuật toán, gửi một thông điệp, xem từng bước handshake và metric, xuất log JSON. TLS 1.2 và TLS 1.3 chạy ở chế độ **mô hình từng bước**: chuỗi bước và phần giải thích theo [The Illustrated TLS 1.2 Connection](https://tls12.xargs.org) và [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org) của Michael Driscoll (giấy phép MIT), được viết lại ngắn gọn bằng tiếng Việt. Giao diện web mở trên máy của bạn; dữ liệu không được gửi tới dịch vụ bên ngoài.

## Cách chạy trên Linux

Yêu cầu Python 3.12 trở lên. Mở terminal tại thư mục dự án. Lần đầu, tạo môi trường và cài thư viện bằng một trong hai cách:

```bash
# Cách 1: nếu đã cài uv
uv sync --extra dev
```

```bash
# Cách 2: dùng Python và pip
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Nếu lệnh tạo môi trường báo thiếu `venv`, hãy cài gói `python3-venv` tương ứng với Python trên hệ điều hành. Sau khi cài, chạy ứng dụng:

```bash
.venv/bin/python -m ssl_tls_lab gui
```

Trình duyệt sẽ tự mở. Nếu không, mở địa chỉ được in trong terminal; giữ terminal đang chạy và nhấn `Ctrl+C` khi muốn dừng. Để dùng cổng cố định, chạy `.venv/bin/python -m ssl_tls_lab gui --port 8765` rồi mở `http://127.0.0.1:8765/`.

Trên giao diện, chọn phiên bản và các thuật toán; nhập thông điệp rồi bấm **Chạy từng bước**. Bấm từng bước để xem giải thích, công thức, đầu vào và đầu ra; dùng nút **Xuất JSON** để lưu log. Kiểm tra môi trường bằng:

```bash
.venv/bin/python -m ssl_tls_lab doctor
```

TLS 1.2 và TLS 1.3 không cần Docker. Muốn chạy SSL 2.0–TLS 1.1 cần Docker đang chạy và build image theo hướng dẫn bên dưới. SSL 1.0 chỉ có thông tin lịch sử, không chạy được trong ứng dụng.

## Mô hình từng bước TLS 1.2 / 1.3

Mỗi lần chạy sinh khóa mới và dựng từng thông điệp handshake với đúng định dạng byte của TLS. A là client, B là server. Mọi record đi qua một kết nối TCP loopback. Mỗi bên tự tính khóa, giải mã thông điệp của bên kia và kiểm tra Finished.

| TLS 1.3 | TLS 1.2 |
| ------- | ------- |
| Client Key Exchange Generation → Client Hello → Server Key Exchange Generation → Server Hello → Server/Client Handshake Keys Calc → Server Change Cipher Spec → Encrypted Extensions → Certificate → Certificate Verify → Server Finished → Server/Client Application Keys Calc → Client Change Cipher Spec → Client Finished → Client Application Data | Client Hello → Server Hello → Server Certificate → Server Key Exchange Generation → Server Key Exchange → Server Hello Done → Client Key Exchange Generation → Client Key Exchange → Client Encryption Keys Calculation → Client Change Cipher Spec → Client Finished → Server Encryption Keys Calculation → Server Change Cipher Spec → Server Finished → Client Application Data |

Bước đầu tiên tạo CA thử nghiệm và chứng chỉ của B; bước cuối là B kiểm tra tag và giải mã. Mỗi bước có 2–3 câu giải thích, công thức dẫn xuất khóa nếu có, record dạng hex và các trường chính. So với tài liệu gốc:

- Các «Wrapped Record» của TLS 1.3 được gộp vào bước của thông điệp bên trong.
- Bỏ New Session Ticket, phản hồi «pong» của server và close_notify.
- Thuật toán theo lựa chọn của bạn. TLS 1.2 dùng AES-GCM thay cho AES-CBC + HMAC-SHA1, nên key block chỉ có khóa và IV cố định 4 byte. Với RSA key transport không có bước Server Key Exchange; A mã hóa PreMasterSecret bằng khóa RSA của B.
- TLS 1.2 không dùng extended master secret, giống tài liệu gốc.

Kiểm thử đối chiếu key schedule TLS 1.3, PRF TLS 1.2 và một record đã bọc với các giá trị công bố trong tài liệu gốc. Mô hình không xử lý alert, nối lại phiên hay phân mảnh handshake, nên không dùng thay thư viện TLS.

JSON chứa khóa riêng chứng chỉ, khóa riêng CA, khóa riêng tạm thời của A và B, các bí mật và khóa phiên. Hãy giữ file này ở nơi riêng tư. Trên Linux/macOS, file do CLI ghi với `--output` có quyền `600`.

## Các phiên bản

| Phiên bản    | Cách chạy                                 | Lựa chọn hiện có                                                                                                           |
| ------------ | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| SSL 1.0      | Chỉ nghiên cứu lịch sử                    | Chưa có đặc tả/triển khai công khai được xác minh để chạy                                                                  |
| SSL 2.0      | Container OpenSSL 1.0.2u                  | RSA; RC4-128/MD5, 3DES-CBC/MD5                                                                                             |
| SSL 3.0      | Container OpenSSL 1.0.2u                  | RSA; RC4-128/MD5, 3DES-CBC/SHA-1                                                                                           |
| TLS 1.0, 1.1 | Container OpenSSL 1.0.2u                  | RSA key transport, DHE-2048 hoặc ECDHE P-256; RSA/ECDSA với tổ hợp hợp lệ; AES-128/256-CBC và SHA-1                        |
| TLS 1.2      | Mô hình từng bước                         | RSA key transport, DHE-2048, ECDHE X25519/P-256; RSA/ECDSA với tổ hợp hợp lệ; AES-128-GCM/SHA-256 hoặc AES-256-GCM/SHA-384 |
| TLS 1.3      | Mô hình từng bước                         | ECDHE X25519/P-256 hoặc DHE ffdhe2048; RSA/ECDSA P-256; AES-128-GCM/SHA-256 hoặc AES-256-GCM/SHA-384                       |

Đây là tập cấu hình đại diện, không phải toàn bộ cipher suite của từng phiên bản. RSA dùng khóa 2048 hoặc 3072 bit, ECDSA dùng P-256. RSA key transport và DHE trong TLS 1.0–1.2 chỉ đi cùng xác thực RSA trong tập cấu hình này; ECDSA đi cùng ECDHE. TLS 1.3 tách cipher suite khỏi trao đổi khóa và xác thực. Với backend container, phiên bản/cipher, loại khóa chứng chỉ và nhóm trao đổi khóa thực tế được kiểm tra.

Cần Docker và image `ssl-tls-lab:legacy` để chạy SSL 2.0–TLS 1.1. Build một lần:

```bash
.venv/bin/python -m ssl_tls_lab lab-build
```

Backend cũ chạy trong container `--network none`; A là server phục vụ thông điệp trong HTTP và B là client xác minh chứng chỉ rồi nhận nội dung qua SSL/TLS. Log ghi các đoạn byte trên loopback theo từng chiều, gồm cả handshake và HTTP; mỗi đoạn TCP không nhất thiết trùng ranh giới record. Thời gian thiết lập, mã hóa và giải mã không được tách ra bằng backend này nên để `null`, không tự suy ra. Các giao thức cũ chỉ dùng cho lab.

Chỉ số thời gian đo từng phép ở mức ứng dụng, gồm chi phí Python/OpenSSL; tổng thời gian bao gồm tạo chứng chỉ và khóa. CPU là tổng tiến trình khi có dữ liệu. Không tính header TCP/IP. Số đo một thông điệp không phải benchmark thông lượng mạng.

CLI và kiểm thử:

```bash
.venv/bin/python -m ssl_tls_lab versions
.venv/bin/python -m ssl_tls_lab message --version 'SSL 2.0' --text 'Xin chào B' --output runs/ssl2-message.json
.venv/bin/python -m ssl_tls_lab message --version 'TLS 1.3' --exchange 'ECDHE X25519' --cipher AES-128-GCM --text 'Xin chào B' --output runs/tls13-message.json
.venv/bin/python -m ssl_tls_lab message --version 'TLS 1.2' --exchange 'ECDHE P-256' --authentication 'ECDSA P-256' --text 'Xin chào B' --output runs/tls12-ecdsa.json
.venv/bin/python -m ssl_tls_lab message --version 'TLS 1.2' --text 'Xin chào B' --tamper --output runs/tampered.json
.venv/bin/python -m pytest -q
```

Lệnh cố tình sửa bản ghi trả mã thoát `1` khi B từ chối, và `2` khi cấu hình/lab lỗi. Các báo cáo và dữ liệu benchmark cũ trong `runs/` và `docs/` được giữ lại để tham khảo; ứng dụng hiện tại không cần chúng để chạy.
