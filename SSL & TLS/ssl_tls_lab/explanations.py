"""Educational provenance of values actually recorded by the lab."""


def explain_steps(result):
    mode = result["mode"]
    legacy = result["config"]["version"] in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    roles = (
        "A là server gửi nội dung HTTP; B là client xác minh server."
        if legacy
        else "A là client gửi thông điệp; B là server nhận thông điệp."
    )
    if legacy:
        storage = "Server A tạo khóa và chứng chỉ trong thư mục tạm của container; thư mục bị xóa sau khi chạy. Bản sao được đưa vào kết quả/log."
        server = "A (server)"
    elif mode == "real":
        storage = "Khóa server B được tạo trong bộ nhớ, ghi tạm vào server.key để OpenSSL nạp, sau đó thư mục tạm bị xóa. Bản sao nằm trong kết quả/log."
        server = "B (server)"
    else:
        storage = "Khóa được tạo và dùng trong bộ nhớ tiến trình mô hình; bản sao nằm trong kết quả/log."
        server = "B (server)"

    def explain(key, value, title):
        where = "Trong kết quả của bước hiện tại."
        source = "Được chương trình ghi lại từ bước này hoặc chuyển từ kết quả của bước trước."
        purpose = "Dùng để quan sát đầu vào hoặc kết quả của phép thử."
        if value is None:
            return {
                "location": "Không có trong kết quả bước này.",
                "origin": "Không được ghi lại hoặc không áp dụng cho phép thử.",
                "purpose": "Không thể suy ra giá trị từ trường trống.",
            }
        if "Khóa riêng CA" in key:
            return {
                "location": "CA thử nghiệm; bản sao trong kết quả/log. Không được gửi trong handshake.",
                "origin": "Sinh ngẫu nhiên khóa RSA mới khi chuẩn bị phiên.",
                "purpose": "Ký chứng chỉ server và chứng chỉ CA thử nghiệm.",
            }
        if "Khóa riêng" in key and (
            "chứng chỉ" in key or "ký của B" in key or "RSA của B" in key
        ):
            return {
                "location": f"{server}; bản sao trong kết quả/log. Không gửi khóa riêng qua mạng.",
                "origin": storage,
                "purpose": "Khóa của chứng chỉ: dùng để ký xác thực hoặc giải mã bí mật tiền chủ RSA tùy cấu hình; khác khóa phiên và khóa DH/ECDHE tạm thời.",
            }
        if "Khóa riêng" in key and ("tạm thời" in key or "DH/ECDHE" in key):
            if mode == "real":
                return {
                    "location": "Bên trong OpenSSL ở hai đầu kết nối; không có giá trị khóa trong log.",
                    "origin": "OpenSSL sinh trong handshake; backend hiện tại không trích xuất giá trị này.",
                    "purpose": "Kết hợp với khóa công khai của đầu kia để tính bí mật chung; không được gửi qua mạng.",
                }
            owner = "A" if "của A" in key else "B"
            return {
                "location": f"Trong bộ nhớ phía {owner} của mô hình; bản sao trong kết quả/log, không được gửi qua mạng.",
                "origin": "Sinh mới bằng bộ sinh khóa DH/ECDHE của thư viện cryptography và nguồn ngẫu nhiên hệ điều hành.",
                "purpose": "Kết hợp với khóa công khai tạm thời của phía còn lại để tính bí mật chung.",
            }
        if "Khóa công khai tạm thời" in key:
            owner = "A" if "của A" in key else "B"
            return {
                "location": f"Phía {owner} tạo ra; phía kia sử dụng; bản sao ở log mô hình.",
                "origin": f"Tính từ khóa riêng DH/ECDHE tạm thời của {owner}.",
                "purpose": "Được trao đổi để hai bên tính cùng bí mật chung; không chứa khóa riêng.",
            }
        if "Khóa công khai" in key:
            return {
                "location": f"Trong chứng chỉ của {server} và bản sao log; có thể gửi cho client.",
                "origin": "Được tính từ khóa riêng chứng chỉ server đã sinh trong bước chuẩn bị.",
                "purpose": "Xác minh chữ ký server, hoặc mã hóa bí mật tiền chủ khi dùng RSA key transport.",
            }
        if "Chứng chỉ CA" in key or "Chứng chỉ được tin cậy" in key:
            origin = (
                "Chứng chỉ server tự ký trong container được dùng làm chứng chỉ tin cậy cho client."
                if legacy
                else "CA thử nghiệm tự ký chứng chỉ CA; client được cấu hình tin cậy chứng chỉ này."
            )
            return {
                "location": "Kho tin cậy của client trong lần chạy; bản sao trong kết quả/log.",
                "origin": origin,
                "purpose": "Làm điểm tin cậy để kiểm tra chứng chỉ server.",
            }
        if "Chứng chỉ server" in key:
            origin = (
                "OpenSSL tạo chứng chỉ tự ký cho server trong container."
                if legacy
                else "Chương trình tạo chứng chỉ X.509 chứa khóa công khai server và ký bằng khóa riêng CA thử nghiệm."
            )
            return {
                "location": f"{server} giữ chứng chỉ; client nhận và kiểm tra; bản sao trong log.",
                "origin": origin,
                "purpose": "Gắn danh tính server với khóa công khai để client xác thực.",
            }
        if "Client random" in key or "Server random" in key:
            owner = "client" if "Client" in key else "server"
            return {
                "location": f"Phía {owner} tạo; hai phía mô hình có bản sao; hiển thị trong log.",
                "origin": "32 byte ngẫu nhiên do hệ điều hành cung cấp trong mô hình.",
                "purpose": "Đưa vào dữ liệu ký và dẫn xuất khóa; đây không phải khóa bí mật.",
            }
        if "Bí mật đã mã hóa" in key:
            return {
                "location": "A gửi bản mã sang B; có trong log mô hình.",
                "origin": "A mã hóa bí mật tiền chủ bằng khóa công khai RSA của B với PKCS#1 v1.5.",
                "purpose": "Chuyển bí mật đến B mà không gửi bản rõ.",
            }
        if "Bí mật tiền chủ" in key:
            if "đã mã hóa" in key:
                return {
                    "location": "A gửi bản mã sang B; có trong log mô hình.",
                    "origin": "A mã hóa bí mật tiền chủ bằng khóa công khai RSA của B với PKCS#1 v1.5.",
                    "purpose": "Chuyển bí mật đến B mà không gửi bản rõ.",
                }
            return {
                "location": "A tạo; B thu được sau giải mã; bản sao bí mật có trong log mô hình.",
                "origin": "Mô hình tạo hai byte phiên bản 03 03 và 46 byte ngẫu nhiên; B giải mã bản mã RSA.",
                "purpose": "Đầu vào của PRF để dẫn xuất master secret; không gửi bản rõ qua mạng.",
            }
        if "Bí mật chung" in key or "Bí mật đầu vào" in key:
            return {
                "location": "Được tính độc lập tại A và B; log mô hình hiển thị bản sao.",
                "origin": "Với DHE/ECDHE: khóa riêng của một bên kết hợp khóa công khai tạm thời của bên kia; với RSA: bí mật tiền chủ đã được giải mã.",
                "purpose": "Đầu vào cho phép dẫn xuất khóa phiên; hai phía phải có cùng giá trị.",
            }
        if "Master secret" in key:
            return {
                "location": "Trong bộ nhớ mỗi phía của mô hình và bản sao log.",
                "origin": "TLS 1.2 mô hình dùng PRF với bí mật đầu vào, nhãn master secret và client/server random.",
                "purpose": "Đầu vào cho PRF key expansion; TLS 1.3 mô hình không xuất trường này.",
            }
        if "Khóa phiên" in key and mode == "real":
            return {
                "location": "Trong trạng thái kết nối của OpenSSL; không có giá trị trong log lần này.",
                "origin": "OpenSSL dẫn xuất trong handshake; ứng dụng chưa trích xuất.",
                "purpose": "Bảo vệ TLS record; không đồng nhất với khóa riêng chứng chỉ.",
            }
        if "Khóa A → B" in key or "Khóa AES" in key:
            return {
                "location": "Trong bộ nhớ A và B của mô hình; có bản sao trong log.",
                "origin": "Mỗi phía tự dẫn xuất từ bí mật chung hoặc bí mật tiền chủ và các tham số hiển thị ở bước dẫn xuất.",
                "purpose": "A mã hóa và B xác thực/giải mã bằng AES-GCM; không gửi trực tiếp khóa qua mạng.",
            }
        if "Dữ liệu được ký" in key:
            return {
                "location": "B tạo trong mô hình; A dùng lại để xác minh.",
                "origin": "Nối client random || server random || khóa công khai tạm thời của B.",
                "purpose": "Ràng buộc khóa tạm thời của B với chữ ký xác thực trong mô hình.",
            }
        if key in ("Chữ ký CA", "Xác minh chữ ký"):
            return {
                "location": "Trong kết quả kiểm tra của client và log.",
                "origin": "Thư viện kiểm tra chữ ký bằng khóa công khai CA hoặc khóa công khai server tương ứng.",
                "purpose": "Cho biết chữ ký có hợp lệ; đây là kết quả kiểm tra, không phải byte chữ ký.",
            }
        if "Chữ ký" in key:
            return {
                "location": "Server tạo, client xác minh; kết quả hoặc bản sao hiển thị trong log.",
                "origin": "Do khóa riêng tương ứng ký dữ liệu; chứng chỉ CA ký chứng chỉ server, còn B ký dữ liệu trao đổi khóa trong mô hình.",
                "purpose": "Xác thực nguồn gốc và tính toàn vẹn của dữ liệu đã ký.",
            }
        if "Nonce" in key:
            if mode == "real":
                return {
                    "location": "Một phần nằm trong record nếu có; nonce đầy đủ ở trạng thái OpenSSL.",
                    "origin": "OpenSSL tạo theo phiên bản TLS; trường tường minh được đọc từ record đã chụp.",
                    "purpose": "Tham số AES-GCM cho mỗi record; ứng dụng không trích xuất nonce đầy đủ.",
                }
            return {
                "location": "A tạo trong mô hình, gửi kèm khung cho B; có bản sao trong log.",
                "origin": "12 byte ngẫu nhiên từ os.urandom cho lần mã hóa này.",
                "purpose": "Tham số AES-GCM; cần duy nhất với cùng khóa.",
            }
        if "AAD" in key:
            return {
                "location": "A và B xử lý khi xác thực; có thể xem giá trị mô hình trong log.",
                "origin": "Mô hình ghép chuỗi DEMO và cấu hình; TLS thực do OpenSSL tạo và ứng dụng chưa trích xuất đầy đủ.",
                "purpose": "Được xác thực cùng bản mã nhưng không được mã hóa như nội dung thông điệp.",
            }
        if "Tag" in key or "tag" in key:
            return {
                "location": "A tạo, B kiểm tra; bản sao hoặc kết quả có trong log.",
                "origin": "AES-GCM tạo tag từ khóa, nonce, AAD và bản mã; record thực được tách từ byte quan sát.",
                "purpose": "Kiểm tra tính toàn vẹn và tính xác thực trước khi chấp nhận bản rõ.",
            }
        if (
            "Bản mã" in key
            or "record" in key.lower()
            or "Đoạn TCP" in key
            or "Khung" in key
        ):
            return {
                "location": "Được tạo ở phía gửi, chuyển qua loopback và ghi lại trong log.",
                "origin": "Từ AES-GCM mô hình hoặc byte record/đoạn TCP thực do OpenSSL tạo, tùy bước.",
                "purpose": "Mang dữ liệu được bảo vệ; byte quan sát có thể gồm header và các thành phần giao thức.",
            }
        if "Thông điệp" in key or "Bản rõ" in key or "nội dung HTTP" in key:
            return {
                "location": "A nhập/gửi; B nhận sau khi giải mã; log lưu bản sao nếu có.",
                "origin": "Văn bản người dùng nhập, mã hóa UTF-8; phía nhận có được sau giải mã thành công.",
                "purpose": "Nội dung ứng dụng cần bảo vệ và chuyển từ A sang B.",
            }
        if "SHA-256 nội dung" in key:
            return {
                "location": "Trong kết quả chuẩn bị nội dung HTTP.",
                "origin": "Tính SHA-256 trên byte UTF-8 của thông điệp.",
                "purpose": "Dấu vân tay nội dung để đối chiếu; không phải chữ ký hay khóa.",
            }
        if "seed" in key or "salt" in key or "HKDF info" in key:
            return {
                "location": "Tham số của bước dẫn xuất khóa trong mô hình, được ghi trong log.",
                "origin": "Mô hình ghép nhãn và random cho PRF hoặc tính salt/info theo phép HKDF minh họa.",
                "purpose": "Phân biệt ngữ cảnh và đầu vào của phép dẫn xuất; không phải khóa riêng.",
            }
        if "byte" in key.lower() or "Độ dài" in key or "Số byte" in key:
            return {
                "location": "Chỉ số trong kết quả bước và log.",
                "origin": "Chương trình đếm số byte của dữ liệu hoặc record tương ứng.",
                "purpose": "Cho biết kích thước, không phải bản thân nội dung hay khóa.",
            }
        if "Địa chỉ" in key:
            return {
                "location": "Giao diện mạng loopback của môi trường chạy lab.",
                "origin": "Chương trình chọn 127.0.0.1 trong môi trường tương ứng.",
                "purpose": "Cho A và B trao đổi TCP cục bộ.",
            }
        if "yêu cầu" in key.lower() or key in (
            "Phiên bản",
            "Xác thực server",
            "Thuật toán trao đổi khóa",
            "Mã hóa",
            "Thuật toán",
            "Hash",
            "Hash chữ ký",
            "Kiểu chữ ký",
            "Phương pháp trao đổi khóa",
            "Hàm dẫn xuất",
            "Đệm RSA",
        ):
            return {
                "location": "Trong cấu hình hoặc tham số của bước, hiển thị ở log.",
                "origin": "Do người dùng chọn hoặc do chương trình xác định theo cấu hình và phép toán.",
                "purpose": "Xác định thuật toán và tham số cho bước; với TLS thực cần đối chiếu giá trị thương lượng thực tế.",
            }
        if (
            "thực tế" in key
            or "hợp lệ" in key
            or "khớp" in key.lower()
            or "Kết quả" in key
            or "Xác minh" in key
            or "Xác thực" in key
        ):
            return {
                "location": "Trong kết quả bước và log.",
                "origin": "Từ kiểm tra của chương trình hoặc kết quả OpenSSL/backend trả về.",
                "purpose": "Cho biết phép kiểm tra, giá trị thương lượng hoặc kết quả đối chiếu; không tự thay cho dữ liệu chưa quan sát được.",
            }
        return {"location": where, "origin": source, "purpose": purpose}

    for step in result["steps"]:
        step["context"] = {
            "roles": roles,
            "storage": storage,
            "scope": (
                "Đây là kết nối SSL/TLS thực; chỉ trình bày giá trị backend đã ghi nhận."
                if mode == "real"
                else "Đây là mô hình dùng phép mật mã thực; handshake và khung truyền không tương thích TLS thật."
            ),
        }
        step["explanations"] = {
            section: {
                key: explain(key, value, step["title"])
                for key, value in step[section].items()
            }
            for section in ("inputs", "outputs")
        }
    return result
