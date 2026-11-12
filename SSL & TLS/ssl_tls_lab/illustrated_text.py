"""Short Vietnamese step texts, condensed from The Illustrated TLS 1.2/1.3 Connection.

Source: https://tls13.xargs.org and https://tls12.xargs.org by Michael Driscoll
(MIT License). Each entry is (title, description, formula or None). Text is
formatted with H (hash name), hl (hash length), kl (key length), host.
"""

PREPARE = (
    "Chuẩn bị khóa và chứng chỉ của B",
    "CA thử nghiệm sinh khóa RSA và tự ký chứng chỉ CA; B sinh khóa chứng chỉ và được CA ký chứng chỉ cho tên {host}. A tin cậy chứng chỉ CA. Tài liệu gốc dùng chứng chỉ có sẵn; ở đây khóa được sinh mới mỗi lần chạy.",
    None,
)

APP_DATA_DESC = "A gửi thông điệp bạn nhập trong record application data, mã hóa bằng client {stage} key. Nếu bật «Thử sửa bản ghi», byte cuối của record bị đảo một bit trên đường truyền."
DECRYPT = (
    "B xác thực tag và giải mã",
    "B giải mã record bằng cùng khóa và nonce. AES-GCM kiểm tra auth tag trước khi trả bản rõ; nếu record bị sửa, B hủy record và không trả dữ liệu nào.",
    None,
)

TLS13 = {
    "prepare": PREPARE,
    "client_keygen": (
        "Client Key Exchange Generation",
        "A sinh cặp khóa tạm thời cho trao đổi khóa. Khóa riêng là số ngẫu nhiên giữ bí mật; khóa công khai tính từ khóa riêng và sẽ được gửi trong Client Hello. Nhờ trao đổi khóa, hai bên có cùng một số mà người nghe lén không tính được.",
        None,
    ),
    "client_hello": (
        "Client Hello",
        "A mở phiên: gửi client random, danh sách cipher suite, các extension (tên server, nhóm, thuật toán chữ ký, phiên bản 1.3) và key share chứa khóa công khai tạm thời. Header record vẫn ghi phiên bản cũ 03 01; phiên bản thật nằm trong extension supported_versions.",
        None,
    ),
    "server_keygen": (
        "Server Key Exchange Generation",
        "B sinh cặp khóa tạm thời của mình trên cùng nhóm mà A đã gửi key share.",
        None,
    ),
    "server_hello": (
        "Server Hello",
        "B trả server random, cipher suite được chọn, phiên bản 1.3 và key share chứa khóa công khai tạm thời của B. Session ID được lặp lại từ A để giống một phiên TLS 1.2. Đây là record cuối cùng gửi ở dạng rõ.",
        None,
    ),
    "server_hs_keys": (
        "Server Handshake Keys Calc",
        "B nhân khóa công khai của A với khóa riêng của mình để được shared secret, rồi đưa shared secret và hash {H} của Client Hello + Server Hello (hello_hash, không gồm header record 5 byte) vào chuỗi HKDF để có khóa và IV mã hóa phần còn lại của handshake.",
        "early_secret = HKDF-Extract(salt: 00, key: 00...)\n"
        "empty_hash = {H}(\"\")\n"
        "derived_secret = HKDF-Expand-Label(key: early_secret, label: \"derived\", ctx: empty_hash, len: {hl})\n"
        "handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)\n"
        "client_secret = HKDF-Expand-Label(key: handshake_secret, label: \"c hs traffic\", ctx: hello_hash, len: {hl})\n"
        "server_secret = HKDF-Expand-Label(key: handshake_secret, label: \"s hs traffic\", ctx: hello_hash, len: {hl})\n"
        "client_handshake_key = HKDF-Expand-Label(key: client_secret, label: \"key\", ctx: \"\", len: {kl})\n"
        "server_handshake_key = HKDF-Expand-Label(key: server_secret, label: \"key\", ctx: \"\", len: {kl})\n"
        "client_handshake_iv = HKDF-Expand-Label(key: client_secret, label: \"iv\", ctx: \"\", len: 12)\n"
        "server_handshake_iv = HKDF-Expand-Label(key: server_secret, label: \"iv\", ctx: \"\", len: 12)",
    ),
    "client_hs_keys": (
        "Client Handshake Keys Calc",
        "A nhân khóa công khai của B với khóa riêng của mình. Tính chất của phép trao đổi khóa cho ra cùng shared secret như B, nên phần tính HKDF còn lại giống hệt và A có cùng khóa, IV handshake.",
        None,
    ),
    "server_ccs": (
        "Server Change Cipher Spec",
        "Record này không còn tác dụng trong TLS 1.3. Nó chỉ được gửi ở «middlebox compatibility mode» để phiên trông giống TLS 1.2.",
        None,
    ),
    "server_ee": (
        "Server Encrypted Extensions",
        "Từ đây handshake được mã hóa bằng server handshake key. Mỗi thông điệp được bọc trong record trông như application data (17 03 03); sau khi giải mã, byte cuối cho biết kiểu thật (16 = handshake). Nonce = IV XOR số thứ tự record; header 5 byte là dữ liệu xác thực bổ sung. Ở đây danh sách extension rỗng.",
        None,
    ),
    "server_cert": (
        "Server Certificate",
        "B gửi chứng chỉ của mình (đã mã hóa). A kiểm tra chữ ký của CA, tên {host} và thời hạn.",
        None,
    ),
    "server_cert_verify": (
        "Server Certificate Verify",
        "Vì khóa trao đổi là khóa tạm thời, B phải chứng minh mình giữ khóa riêng của chứng chỉ: B ký hash các thông điệp handshake đến Certificate. A xác minh chữ ký bằng khóa công khai trong chứng chỉ.",
        "dữ liệu ký = 64 byte 0x20 + \"TLS 1.3, server CertificateVerify\" + 00 + {H}(Client Hello ... Certificate)",
    ),
    "server_finished": (
        "Server Handshake Finished",
        "B tính verify_data từ server handshake traffic secret và hash mọi thông điệp handshake từ Client Hello đến Certificate Verify. A tự tính và so sánh để chắc handshake không bị sửa.",
        "finished_key = HKDF-Expand-Label(key: server_secret, label: \"finished\", ctx: \"\", len: {hl})\n"
        "finished_hash = {H}(Client Hello ... Server Cert Verify)\n"
        "verify_data = HMAC-{H}(key: finished_key, msg: finished_hash)",
    ),
    "server_app_keys": (
        "Server Application Keys Calc",
        "B dẫn xuất khóa cho dữ liệu ứng dụng từ handshake secret và hash mọi thông điệp handshake từ Client Hello đến Server Finished (bỏ header record của hai Hello và byte kiểu ở cuối các record đã bọc).",
        "empty_hash = {H}(\"\")\n"
        "derived_secret = HKDF-Expand-Label(key: handshake_secret, label: \"derived\", ctx: empty_hash, len: {hl})\n"
        "master_secret = HKDF-Extract(salt: derived_secret, key: 00...)\n"
        "client_secret = HKDF-Expand-Label(key: master_secret, label: \"c ap traffic\", ctx: handshake_hash, len: {hl})\n"
        "server_secret = HKDF-Expand-Label(key: master_secret, label: \"s ap traffic\", ctx: handshake_hash, len: {hl})\n"
        "client_application_key = HKDF-Expand-Label(key: client_secret, label: \"key\", ctx: \"\", len: {kl})\n"
        "server_application_key = HKDF-Expand-Label(key: server_secret, label: \"key\", ctx: \"\", len: {kl})\n"
        "client_application_iv = HKDF-Expand-Label(key: client_secret, label: \"iv\", ctx: \"\", len: 12)\n"
        "server_application_iv = HKDF-Expand-Label(key: server_secret, label: \"iv\", ctx: \"\", len: 12)",
    ),
    "client_app_keys": (
        "Client Application Keys Calc",
        "A thực hiện cùng phép tính với cùng handshake secret và handshake hash nên có cùng khóa và IV ứng dụng.",
        None,
    ),
    "client_ccs": (
        "Client Change Cipher Spec",
        "Giống phía server: record không có tác dụng trong TLS 1.3, chỉ giúp phiên trông giống TLS 1.2.",
        None,
    ),
    "client_finished": (
        "Client Handshake Finished",
        "A tính verify_data từ client handshake traffic secret và hash handshake đến Server Finished, mã hóa bằng client handshake key (số thứ tự 0). B tự tính và so sánh.",
        "finished_key = HKDF-Expand-Label(key: client_secret, label: \"finished\", ctx: \"\", len: {hl})\n"
        "finished_hash = {H}(Client Hello ... Server Finished)\n"
        "verify_data = HMAC-{H}(key: finished_key, msg: finished_hash)",
    ),
    "client_app_data": (
        "Client Application Data",
        APP_DATA_DESC.replace("{stage}", "application")
        + " Byte 17 ở cuối bản rõ bên trong cho biết kiểu application data.",
        None,
    ),
    "server_decrypt": DECRYPT,
}

TLS12 = {
    "prepare": PREPARE,
    "client_hello": (
        "Client Hello",
        "A mở phiên: gửi client random, danh sách cipher suite (suite theo cấu hình đứng đầu), phương thức nén (chỉ null) và các extension như tên server, nhóm đường cong, thuật toán chữ ký, renegotiation_info.",
        None,
    ),
    "server_hello": (
        "Server Hello",
        "B trả server random, session ID dùng để nối lại phiên sau này, và cipher suite được chọn từ danh sách của A.",
        None,
    ),
    "server_cert": (
        "Server Certificate",
        "B gửi chứng chỉ chứa khóa công khai của mình. A kiểm tra chữ ký của CA, tên {host} và thời hạn.",
        None,
    ),
    "server_keygen": (
        "Server Key Exchange Generation",
        "B sinh cặp khóa tạm thời cho trao đổi khóa. Khóa riêng là số ngẫu nhiên giữ bí mật; khóa công khai tính từ khóa riêng và được gửi trong Server Key Exchange.",
        None,
    ),
    "server_kx": (
        "Server Key Exchange",
        "B gửi tham số trao đổi khóa và khóa công khai tạm thời, kèm chữ ký bằng khóa riêng của chứng chỉ. Chữ ký phủ cả client random và server random nên không thể dùng lại ở phiên khác; A xác minh bằng khóa công khai trong chứng chỉ.",
        "dữ liệu ký = client_random + server_random + tham số khóa của B",
    ),
    "server_hello_done": (
        "Server Hello Done",
        "B báo đã gửi xong phần handshake của mình. Thông điệp rỗng.",
        None,
    ),
    "client_keygen": (
        "Client Key Exchange Generation",
        "A sinh cặp khóa tạm thời trên cùng nhóm với B.",
        None,
    ),
    "client_keygen_rsa": (
        "Client Key Exchange Generation",
        "Với RSA key transport không có Server Key Exchange. A tự sinh PreMasterSecret 48 byte (03 03 + 46 byte ngẫu nhiên) và mã hóa bằng khóa công khai RSA trong chứng chỉ của B. Cách này không có forward secrecy: ai có khóa riêng của chứng chỉ đều giải mã được phiên đã ghi lại.",
        None,
    ),
    "client_kx": (
        "Client Key Exchange",
        "A gửi khóa công khai tạm thời của mình để B tính cùng bí mật chung.",
        None,
    ),
    "client_kx_rsa": (
        "Client Key Exchange",
        "A gửi PreMasterSecret đã mã hóa RSA; chỉ B, người có khóa riêng của chứng chỉ, giải mã được.",
        None,
    ),
    "client_keys": (
        "Client Encryption Keys Calculation",
        "A có PreMasterSecret (với DHE/ECDHE là bí mật chung từ khóa riêng của A và khóa công khai của B). A dùng PRF để tính MasterSecret 48 byte rồi mở rộng thành khóa. Tài liệu gốc dùng AES-CBC nên có thêm MAC key; ở đây AES-GCM chỉ cần hai khóa và hai IV cố định 4 byte.",
        "seed = \"master secret\" + client_random + server_random\n"
        "a0 = seed\n"
        "a1 = HMAC-{H}(key=PreMasterSecret, data=a0)\n"
        "a2 = HMAC-{H}(key=PreMasterSecret, data=a1)\n"
        "p1 = HMAC-{H}(key=PreMasterSecret, data=a1 + seed)\n"
        "p2 = HMAC-{H}(key=PreMasterSecret, data=a2 + seed)\n"
        "MasterSecret = (p1 + p2 + ...)[48 byte đầu]\n"
        "\n"
        "seed = \"key expansion\" + server_random + client_random\n"
        "key_block = P_{H}(MasterSecret, seed)\n"
        "client write key = key_block[0:{kl}], server write key = tiếp {kl} byte\n"
        "client write IV = tiếp 4 byte, server write IV = 4 byte sau đó",
    ),
    "client_ccs": (
        "Client Change Cipher Spec",
        "A báo rằng mọi record tiếp theo của mình sẽ được mã hóa bằng khóa vừa tính.",
        None,
    ),
    "client_finished": (
        "Client Handshake Finished",
        "A tính verify_data từ hash mọi thông điệp handshake (không gồm header record) và mã hóa bằng client write key. Nonce AES-GCM = IV cố định 4 byte + nonce tường minh 8 byte gửi kèm record; dữ liệu xác thực bổ sung gồm số thứ tự, kiểu, phiên bản và độ dài.",
        "verify_data = PRF(MasterSecret, \"client finished\", {H}(handshake messages))[0:12]",
    ),
    "server_keys": (
        "Server Encryption Keys Calculation",
        "B tính bí mật chung từ khóa riêng của B và khóa công khai A gửi, rồi chạy cùng PRF nên có cùng MasterSecret và khóa. B giải mã Finished của A và kiểm tra verify_data.",
        None,
    ),
    "server_keys_rsa": (
        "Server Encryption Keys Calculation",
        "B giải mã PreMasterSecret bằng khóa riêng RSA của chứng chỉ, rồi chạy cùng PRF nên có cùng MasterSecret và khóa. B giải mã Finished của A và kiểm tra verify_data.",
        None,
    ),
    "server_ccs": (
        "Server Change Cipher Spec",
        "B báo rằng mọi record tiếp theo của mình sẽ được mã hóa.",
        None,
    ),
    "server_finished": (
        "Server Handshake Finished",
        "B tính verify_data từ hash handshake, lần này gồm cả Finished của A, và mã hóa bằng server write key. A tự tính và so sánh.",
        "verify_data = PRF(MasterSecret, \"server finished\", {H}(handshake messages))[0:12]",
    ),
    "client_app_data": (
        "Client Application Data",
        APP_DATA_DESC.replace("{stage}", "write") + " Số thứ tự record là 1 vì Finished đã dùng số 0.",
        None,
    ),
    "server_decrypt": DECRYPT,
}
