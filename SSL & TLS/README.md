# SSL/TLS: hành trình thông điệp A → B

Ứng dụng cục bộ cho bài tập mật mã: chọn phiên bản và thuật toán, gửi một thông điệp, quan sát các bước và metric, xuất log JSON. Giao diện mặc định chọn **Kết nối thực** với nút **Chạy kết nối thực**. Giao diện web mở trên máy của bạn; dữ liệu không được gửi tới dịch vụ bên ngoài.

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

Trên giao diện, chọn **Kết nối thực**, phiên bản và các thuật toán; nhập thông điệp rồi bấm **Chạy kết nối thực**. Bấm từng bước để xem đầu vào, đầu ra và giải thích; dùng nút **Xuất JSON** để lưu log. Kiểm tra môi trường bằng:

```bash
.venv/bin/python -m ssl_tls_lab doctor
```

TLS 1.2 và TLS 1.3 không cần Docker. Muốn chạy SSL 2.0–TLS 1.1 cần Docker đang chạy và build image theo hướng dẫn bên dưới. SSL 1.0 chỉ có thông tin lịch sử, không chạy được trong ứng dụng.

Khi chọn một bước, bảng chi tiết hiển thị riêng **tham số đầu vào** và **kết quả đầu ra**. Mỗi giá trị có giải thích **nằm ở đâu**, **sinh ra/lấy từ đâu** và **dùng để làm gì**; phần đầu cho biết vai trò A/B và nơi lưu khóa. JSON lưu các giá trị dưới `inputs`, `outputs` và giải thích dưới `context`, `explanations`. Với kết nối thực, giá trị nội bộ mà OpenSSL không cung cấp được ghi rõ là không quan sát được; không thay bằng dữ liệu từ mô hình.

Ở bước chuẩn bị kết nối thực, phần phép toán RSA hiển thị `p`, `q`, `n`, `e`, `d` của khóa chứng chỉ RSA và khóa CA được tạo trong lần chạy, cùng các quan hệ toán học giữa chúng. Các tham số được trích xuất từ khóa sau khi sinh; quá trình chọn số nguyên tố bên trong OpenSSL không được ghi lại. Chúng là dữ liệu bí mật và cũng nằm trong JSON xuất ra.

| Phiên bản    | Chạy thực                                 | Lựa chọn hiện có                                                                                                           |
| ------------ | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| SSL 1.0      | Chỉ nghiên cứu lịch sử                    | Chưa có đặc tả/triển khai công khai được xác minh để chạy                                                                  |
| SSL 2.0      | Container OpenSSL 1.0.2u                  | RSA; RC4-128/MD5, 3DES-CBC/MD5                                                                                             |
| SSL 3.0      | Container OpenSSL 1.0.2u                  | RSA; RC4-128/MD5, 3DES-CBC/SHA-1                                                                                           |
| TLS 1.0, 1.1 | Container OpenSSL 1.0.2u                  | RSA key transport, DHE-2048 hoặc ECDHE P-256; RSA/ECDSA với tổ hợp hợp lệ; AES-128/256-CBC và SHA-1                        |
| TLS 1.2      | Python ssl/OpenSSL                        | RSA key transport, DHE-2048, ECDHE X25519/P-256; RSA/ECDSA với tổ hợp hợp lệ; AES-128-GCM/SHA-256 hoặc AES-256-GCM/SHA-384 |
| TLS 1.3      | Python ssl/OpenSSL trong tiến trình riêng | ECDHE X25519/P-256 hoặc DHE ffdhe2048; RSA/ECDSA P-256; AES-128-GCM/SHA-256 hoặc AES-256-GCM/SHA-384                       |

Đây là tập cấu hình đại diện, không phải toàn bộ cipher suite của từng phiên bản. RSA dùng khóa 2048 hoặc 3072 bit, ECDSA dùng P-256. RSA key transport và DHE trong TLS 1.0–1.2 chỉ đi cùng xác thực RSA trong tập cấu hình này; ECDSA đi cùng ECDHE. TLS 1.3 tách cipher suite khỏi trao đổi khóa và xác thực. Phiên bản/cipher, loại khóa chứng chỉ và nhóm trao đổi khóa thực tế được kiểm tra; TLS 1.3 dùng OpenSSL configuration riêng cho tiến trình con để chọn đúng cipher suite.

Cần Docker và image `ssl-tls-lab:legacy` để chạy SSL 2.0–TLS 1.1. Build một lần:

```bash
.venv/bin/python -m ssl_tls_lab lab-build
```

Backend cũ chạy trong container `--network none`; A là server phục vụ thông điệp trong HTTP và B là client xác minh chứng chỉ rồi nhận nội dung qua SSL/TLS. Log ghi các đoạn byte trên loopback theo từng chiều, gồm cả handshake và HTTP; mỗi đoạn TCP không nhất thiết trùng ranh giới record. Thời gian thiết lập, mã hóa và giải mã không được tách ra bằng backend này nên để `null`, không tự suy ra. Các giao thức cũ chỉ dùng cho lab.

TLS 1.2/1.3 thực dùng `ssl.MemoryBIO` và TCP loopback: hiển thị TLS record, phiên bản/suite đã thương lượng, kết quả kiểm tra hostname/chứng chỉ, thời gian handshake và gửi/nhận. Chọn **Thử sửa bản ghi khi truyền** để xem B từ chối record lỗi; thử nghiệm này hiện chưa hỗ trợ các backend cũ. API `ssl` đang dùng không xuất khóa riêng DH/ECDHE tạm thời; công cụ chưa trích xuất khóa phiên từ OpenSSL.

Chế độ **Mô hình từng bước** hỗ trợ TLS 1.2/1.3 để xem bí mật, RSA/DHE/ECDHE, chữ ký RSA/ECDSA, PRF/HKDF, AES-GCM và tag. Đây là phép mật mã thực nhưng handshake/khung truyền là mô hình học tập: mô hình TLS 1.2 chưa có extended master secret và Finished; TLS 1.3 dùng HKDF minh họa, chưa có đầy đủ key schedule/Finished. Không xem mô hình là giao thức TLS tương thích wire.

Bước chuẩn bị hiển thị khóa riêng chứng chỉ server do lab tạo, và khóa riêng CA thử nghiệm nếu có. Trong chế độ mô hình, bước ký còn hiển thị khóa riêng DH/ECDHE tạm thời của A và B; đây là khóa của mô hình, không phải khóa tạm thời của kết nối TLS thực. JSON của cả hai chế độ chứa khóa riêng thử nghiệm và cần được giữ riêng. File do CLI ghi với `--output` có quyền `600`; quyền của file tải từ trình duyệt do trình duyệt và hệ điều hành quyết định.

Chỉ số thời gian đo từng phép ở mức ứng dụng, gồm chi phí Python/OpenSSL; tổng thời gian bao gồm tạo chứng chỉ và khóa. CPU là tổng tiến trình khi có dữ liệu. Không tính header TCP/IP. Số đo một thông điệp không phải benchmark thông lượng mạng.

CLI và kiểm thử:

```bash
.venv/bin/python -m ssl_tls_lab versions
.venv/bin/python -m ssl_tls_lab message --version 'SSL 2.0' --text 'Xin chào B' --output runs/ssl2-message.json
.venv/bin/python -m ssl_tls_lab message --version 'TLS 1.3' --exchange 'ECDHE X25519' --cipher AES-128-GCM --text 'Xin chào B' --output runs/tls13-message.json
.venv/bin/python -m ssl_tls_lab message --version 'TLS 1.2' --exchange 'ECDHE P-256' --authentication 'ECDSA P-256' --text 'Xin chào B' --output runs/tls12-ecdsa.json
.venv/bin/python -m ssl_tls_lab message --version 'TLS 1.2' --text 'Xin chào B' --tamper --output runs/tampered.json
.venv/bin/python -m ssl_tls_lab message --mode model --version 'TLS 1.2' --text 'Xin chào B'
.venv/bin/python -m pytest -q
```

Lệnh cố tình sửa bản ghi trả mã thoát `1` khi B từ chối, và `2` khi cấu hình/lab lỗi. Các báo cáo và dữ liệu benchmark cũ trong `runs/` và `docs/` được giữ lại để tham khảo; ứng dụng hiện tại không cần chúng để chạy.
