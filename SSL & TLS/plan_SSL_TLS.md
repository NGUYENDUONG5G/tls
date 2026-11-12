# Kế hoạch bài tập SSL/TLS

## 1. Mục tiêu và quyết định

Xây dựng công cụ học tập tiếng Việt để nghiên cứu đầy đủ lịch sử SSL 1.0 → TLS 1.3, cách kết hợp thuật toán và các metric so sánh có phương pháp rõ ràng.

- Python 3.12+, OpenSSL CLI qua subprocess, không viết C.
- Desktop Tkinter, biểu đồ Matplotlib; CLI dùng cùng lớp dịch vụ.
- Danh mục đầy đủ theo snapshot IANA, bổ sung SSL lịch sử; đo ma trận đại diện.
- Backend OpenSSL 1.0.2u và 3.5.5 trong Docker `--network none`.
- Xuất JSON, CSV, Markdown, PNG, SVG; mọi số liệu truy được về log và môi trường.
- SSL 1.0 nghiên cứu lịch sử; không gán suite hoặc dữ liệu giả khi chưa có triển khai công khai được xác minh.

Tài liệu này đã được lưu khi chuyển sang triển khai. Xem README, docs/validation.md cho kiểm chứng ban đầu và docs/full_benchmark.md cho lần chạy đầy đủ 30 mẫu/payload, 3 batch × 10 giây đã hoàn thành.

## 2. Nghiên cứu và danh mục

| Phiên bản | Nội dung                                                    | Thực nghiệm                    |
| --------- | ----------------------------------------------------------- | ------------------------------ |
| SSL 1.0   | Bối cảnh, tình trạng tài liệu, những chi tiết chưa xác minh | Không                          |
| SSL 2.0   | Handshake, RSA, bộ mã cổ, hạn chế thiết kế; RFC 6176        | Có, legacy                     |
| SSL 3.0   | Record/MAC, thay đổi thiết kế, CBC/POODLE; RFC 6101/7568    | Có, legacy                     |
| TLS 1.0   | PRF MD5/SHA-1, HMAC, IV liên kết, RFC 2246/8996             | Có, legacy                     |
| TLS 1.1   | Explicit IV và thay đổi padding, RFC 4346/8996              | Có, legacy                     |
| TLS 1.2   | PRF, AEAD, chữ ký và trao đổi khóa, RFC 5246/5288/9325      | Có, modern và đối chứng legacy |
| TLS 1.3   | HKDF, AEAD, key share, chữ ký, session tickets, RFC 8446    | Có; 0-RTT lý thuyết            |

Mỗi hồ sơ ghi năm xuất hiện/năm RFC riêng, trạng thái, đặc tính, hạn chế và nguồn. Nguồn không đủ phải ghi “chưa xác minh”. Danh mục phân biệt suite, signaling, nhóm khóa, chữ ký, reserved và unassigned. Không dùng nhãn của `openssl ciphers -v` để tự suy ra khả năng giao thức.

Các trường suite: mã/tên chuẩn, tên OpenSSL nếu đã đối chiếu, phiên bản đã duyệt, nguồn, trạng thái registry; key exchange; xác thực; thuật toán/mode; số bit khóa; MAC/tag; hash và vai trò; AEAD/PFS. Thuộc tính chưa phân tích được dùng null. TLS 1.3 tách suite, nhóm và chữ ký. Không cộng độ dài khóa thành “điểm bảo mật”.

Lưu registry gốc cùng checksum và ngày lấy dữ liệu; cập nhật bằng CLI riêng. Mỗi run lưu một bản snapshot để báo cáo tái lập ngoại tuyến. Các họ PSK/SRP/anonymous/NULL và thuật toán chuyên biệt có trong danh mục, không bắt buộc benchmark.

## 3. Kiến trúc và lab

Luồng: CLI/Desktop → cấu hình → kiểm tra hợp lệ → backend/certificate → server → probe thương lượng → warm-up → benchmark → checkpoint/log → thống kê/báo cáo.

Các lớp: catalog, backend adapter, worker đo trong container, service điều phối, report và GUI. GUI không xử lý giao thức trực tiếp, không thao tác widget từ thread nền.

Build nguồn OpenSSL có checksum, pin digest base image, lưu build flags, version-a và image ID. Legacy phải probe được SSL 2.0 và SSL 3.0 trước khi sẵn sàng. Không thay thư viện hệ thống; không mở cổng lab ra host. Thiếu Docker vẫn đọc danh mục/kết quả được.

Chứng chỉ CA chung, RSA-2048/3072, ECDSA P-256/P-384; cùng độ dài chain. DHE dùng MODP 2048 bit. Chuẩn bị chứng chỉ, tham số và payload trước phép đo. Client/server cùng container qua loopback; timer không bao gồm docker exec.

## 4. Ma trận 39 cấu hình

| Phiên bản/nhóm | Cấu hình                                                                                                                                                 |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSL 2.0        | RC4-128/MD5, 3DES/MD5, RC4-40 export/MD5                                                                                                                 |
| SSL 3.0        | RSA + RC4/MD5, RSA + 3DES/SHA-1                                                                                                                          |
| TLS 1.0/1.1    | RSA + AES-128/256-CBC; DHE-RSA + AES-128-CBC; ECDHE-RSA + AES-128-CBC                                                                                    |
| TLS 1.2        | ECDHE × RSA/ECDSA × AES-128/256-GCM/ChaCha20; DHE-RSA + AES-128-GCM; RSA transport + AES-128-GCM; ECDHE-RSA + AES-128-CBC/SHA256; RSA + AES-128-CBC/SHA1 |
| TLS 1.3        | AES-128-GCM/AES-256-GCM/ChaCha20 × RSA/ECDSA; AES-128-CCM/CCM-8 + RSA                                                                                    |
| Sweep          | Trên AES-128-GCM của TLS 1.2/1.3: RSA-3072, ECDSA P-384, ECDHE P-256                                                                                     |
| Bridge         | TLS 1.2 ECDHE-RSA/AES-128-GCM/P-256 legacy, đối chiếu modern                                                                                             |
| Hybrid         | TLS 1.3 AES-128-GCM/RSA với X25519MLKEM768                                                                                                               |

Mặc định dùng RSA-2048/ECDSA P-256, X25519 modern hoặc P-256 legacy. Không thương lượng suite khác để thay thế một hàng. Không hỗ trợ vẫn lưu nguyên hàng và lý do. Giữ nguyên các yếu tố khác khi so sánh từng thành phần. Với ECDSA TLS 1.2 phải cho phép đường cong chứng chỉ trong supported_groups, đồng thời kiểm tra nhóm ephemeral thực tế.

## 5. Metric và phương pháp

| Metric                         | Phương pháp/giới hạn                                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| Protocol/suite/group/signature | Parse bằng chứng thương lượng; không lấy giá trị yêu cầu làm kết quả                    |
| Setup connections/s            | s_time -new, không HTTP; có TCP và vòng lặp công cụ                                     |
| Setup mean ms                  | 1000 × reported real seconds / connections; không phải SSL_connect thuần                |
| E2E latency ms                 | perf_counter_ns quanh s_client; bao gồm process/TCP/TLS/payload/close                   |
| Payload MiB/s                  | Payload đủ byte, đúng SHA-256 / thời gian E2E                                           |
| Batch HTTP bytes/s             | s_time -www; có thể gồm HTTP header                                                     |
| CPU                            | User+system client, delta server; không dùng CPU toàn máy                               |
| RSS                            | Đỉnh quan sát client 10 ms, server quan sát; thiếu mẫu dùng null                        |
| Success rate                   | Đạt / tất cả lần thử cùng loại, giữ cả lỗi                                              |
| Resumption                     | Session ticket/session input và dấu hiệu tái sử dụng thực tế; từng batch cần kiểm tra r |
| Security properties            | Khóa, tag/MAC, AEAD, PFS từ định nghĩa và cấu hình; không phải hiệu năng                |
| RTT/0-RTT/vulnerability        | Lý thuyết có nguồn; không gắn nhãn đo packet                                            |

Quy trình mặc định: concurrency 1; 5 warm-up; 30 mẫu cho mỗi payload 1 KiB/16 MiB; 3 batch × 10 giây; tách setup/HTTP và new/reuse; seed 20261108 để xáo trộn. Probe timeout 5 giây, truyền đơn 30 giây, batch mặc định tối đa 20 giây. Khi đổi độ dài batch, timeout bằng batch_seconds + 10.

Thống kê gồm n, mean, median, p95, min/max, stdev; chỉ tính p95 cho mẫu đơn E2E, không suy từ trung bình batch. Không thay mẫu lỗi bằng 0. Cấu hình/metric không hỗ trợ phải có reason. Lưu UTC timestamp, CPU/OS/Python/OpenSSL/build/certificate/group và thứ tự chạy. So sánh backend phải nêu yếu tố thư viện.

## 6. CLI, dữ liệu và desktop

CLI: doctor, history, catalog, catalog-update, matrix, lab-build, probe --config, benchmark --profile, report --run, gui. Nhận danh sách cấu hình JSON; cùng service với GUI.

Mỗi run/sample có schema_version, run_id, config_id, backend, requested/observed, kind, status, reason, metric có đơn vị và log. Trạng thái success/unsupported/failed/timeout/cancelled. Giá trị thiếu null; CSV ô trống, Markdown —. Ghi checkpoint nguyên tử sau mỗi mẫu để hủy vẫn giữ dữ liệu.

Desktop gồm năm tab: Lịch sử; Thuật toán; Thực nghiệm; So sánh; Báo cáo. Có bộ lọc, đa chọn cấu hình, profile, số mẫu, chạy/dừng, tiến độ, mở run cũ, biểu đồ mẫu và xuất báo cáo. Dùng thread/queue/after; không vẽ lại biểu đồ trong cửa sổ benchmark. Đóng app dừng tiến trình/container do app tạo.

Báo cáo: lịch sử, tổ hợp suite và thành phần, trạng thái đầy đủ, dữ liệu/đơn vị/n/backend/method, biểu đồ PNG/SVG, phân tích sai số và yếu tố gây nhiễu, nguồn cùng snapshot. Report đọc dữ liệu cũ, không chạy lại benchmark.

## 7. Triển khai và nghiệm thu

1. Khởi tạo package/CLI/dependency/doctor.
2. Hồ sơ bảy phiên bản, nghiên cứu SSL 1.0, snapshot registry và matrix.
3. Build backend và artifacts; probe thật SSL 2.0 → TLS 1.3.
4. Runner, parser, benchmark, hủy/checkpoint và schema dữ liệu.
5. Desktop năm tab, tác vụ nền, bộ lọc, so sánh.
6. Báo cáo/CSV/JSON/biểu đồ tái tạo từ run.
7. Kiểm thử và chạy representative; ghi trạng thái kiểm chứng thực tế.

Kiểm thử: output cũ/mới/thiếu trường; sai version/suite/group/certificate; không chung suite; đủ byte/SHA; thống kê/null/đơn vị; server chết/timeout/cổng bận/hủy; resumption mới/đã reuse; CSV/JSON/report nhất quán; Docker thiếu; đóng app dọn tài nguyên.

Nghiệm thu: đủ hồ sơ có nguồn; handshake bằng chứng cho sáu bản đã phát hành; tất cả 39 hàng có trạng thái; số liệu truy được về log; không dùng dữ liệu demo; UI/CLI và hướng dẫn Linux tái lập; báo cáo tiếng Việt có dữ liệu và biểu đồ.

Giới hạn bản đầu: SSL/TLS trên TCP/loopback, xác thực server; không triển khai DTLS/QUIC, mTLS, benchmark 0-RTT hoặc khai thác lỗ hổng. Các kết luận hiệu năng chỉ áp dụng môi trường ghi nhận. Bản cũ chỉ chạy lab cô lập.
