"""Attach observable inputs and outputs to each message-exchange step."""

from __future__ import annotations

import hashlib
import math

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def rsa_key_operations(private_pem: str, owner: str) -> list[dict]:
    """Describe the actual generated key, without claiming to observe keygen internals."""
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        return []
    numbers = key.private_numbers()
    p, q, d = numbers.p, numbers.q, numbers.d
    n, e = numbers.public_numbers.n, numbers.public_numbers.e
    lam = math.lcm(p - 1, q - 1)
    hx = lambda value: hex(value)
    return [
        {
            "title": f"Sinh khóa RSA của {owner}",
            "method": "rsa.generate_private_key(public_exponent=e, key_size=...) sinh khóa bằng thư viện cryptography/OpenSSL. p và q được trích xuất sau khi sinh khóa; quá trình chọn và kiểm tra từng số nguyên tố không được ghi lại.",
            "inputs": {"Số bit modulus": key.key_size, "Số mũ công khai e": e},
            "outputs": {
                "Số nguyên tố bí mật p (hex)": hx(p),
                "Số nguyên tố bí mật q (hex)": hx(q),
            },
        },
        {
            "title": f"Các tham số RSA của {owner}",
            "method": "Quan hệ toán học của khóa thực đã sinh: n = p × q; λ(n) = lcm(p − 1, q − 1); e × d ≡ 1 (mod λ(n)). Các phép tính này được kiểm tra lại từ khóa, không phải bản ghi từng phép tính trong OpenSSL.",
            "inputs": {"p (hex)": hx(p), "q (hex)": hx(q), "e": e},
            "outputs": {
                "Modulus n = p × q (hex)": hx(n),
                "λ(n) = lcm(p − 1, q − 1) (hex)": hx(lam),
                "Số mũ bí mật d (hex)": hx(d),
                "e × d mod λ(n)": e * d % lam,
                "Khóa công khai": "(n, e)",
                "Khóa riêng": "(n, d), cùng p, q và các tham số CRT",
            },
        },
    ]


def annotate_steps(result: dict) -> dict:
    steps = result["steps"]
    config = result["config"]
    by_title = {s["title"]: s["details"] for s in steps}
    cert = (
        by_title.get("Tạo khóa và chứng chỉ thử nghiệm")
        or by_title.get("Chuẩn bị khóa và chứng chỉ")
        or by_title.get("Chuẩn bị server và chứng chỉ")
        or {}
    )
    key_step = by_title.get("Dẫn xuất khóa phiên độc lập", {})
    enc = by_title.get("AES-GCM mã hóa và tạo tag", {})
    model_wire = by_title.get("Truyền bản mã qua TCP loopback", {})
    real_enc = by_title.get("Mã hóa thành TLS application record", {})
    real_wire = by_title.get("Truyền TLS record qua TCP loopback", {})
    exchange = (
        by_title.get("RSA mã hóa bí mật tiền chủ")
        or by_title.get("B ký khóa tạm thời")
        or {}
    )
    shared = by_title.get("Kiểm tra chữ ký và tính bí mật chung", {})
    hidden = "Chưa trích xuất hoặc hiển thị khóa phiên từ OpenSSL trong lần chạy này."
    hidden_ephemeral = "API ssl hiện dùng không xuất khóa riêng DH/ECDHE tạm thời."
    hidden_nonce = "API SSLObject không cung cấp trực tiếp nonce đầy đủ và AAD."
    for step in steps:
        title = step["title"]
        d = step["details"]
        if title in (
            "Tạo khóa và chứng chỉ thử nghiệm",
            "Chuẩn bị khóa và chứng chỉ",
            "Chuẩn bị server và chứng chỉ",
        ):
            inputs = {
                "Phiên bản": config["version"],
                "Xác thực server": config["authentication"],
                "Thuật toán trao đổi khóa": config["exchange"],
                "Mã hóa": config["cipher"],
            }
            if config["authentication"] == "RSA" or d.get("ca_certificate_pem"):
                inputs["Khóa RSA (bit)"] = config["rsa_bits"]
            outputs = {
                "Chứng chỉ server (PEM)": d.get("certificate_pem"),
                "Khóa công khai server (PEM)": d.get("server_public_key_pem"),
                "Khóa riêng chứng chỉ server (PEM)": d.get("server_private_key_pem"),
                "Chứng chỉ CA tin cậy (PEM)": d.get(
                    "ca_certificate_pem", d.get("certificate_pem")
                ),
                "Độ dài chứng chỉ (byte)": d.get("certificate_bytes"),
            }
            if d.get("ca_private_key_pem"):
                outputs["Khóa riêng CA thí nghiệm (PEM)"] = d["ca_private_key_pem"]
            if result.get("mode") == "real":
                operations = []
                for field, owner in (
                    ("server_private_key_pem", "server"),
                    ("ca_private_key_pem", "CA"),
                ):
                    if d.get(field):
                        operations.extend(rsa_key_operations(d[field], owner))
                if operations:
                    step["operations"] = operations
        elif title == "Kiểm tra chứng chỉ của B":
            inputs = {
                "Chứng chỉ server (PEM)": cert.get("certificate_pem"),
                "Chứng chỉ CA tin cậy (PEM)": cert.get("ca_certificate_pem"),
                "Tên cần xác minh": "B.local",
            }
            outputs = {
                "Chữ ký CA": d.get("signature"),
                "Tên server": d.get("hostname"),
                "Thời hạn": d.get("validity"),
                "Giới hạn kiểm tra": d.get("note"),
            }
        elif title == "RSA mã hóa bí mật tiền chủ":
            inputs = {
                "Bí mật tiền chủ (hex)": d.get("premaster_secret"),
                "Khóa công khai RSA của B (PEM)": cert.get("server_public_key_pem"),
                "Đệm RSA": "PKCS#1 v1.5",
            }
            outputs = {
                "Bí mật đã mã hóa (hex)": d.get("rsa_ciphertext"),
                "Độ dài bản mã (byte)": d.get("rsa_ciphertext_bytes"),
            }
        elif title == "RSA giải mã bí mật tiền chủ":
            inputs = {
                "Bí mật đã mã hóa (hex)": exchange.get("rsa_ciphertext"),
                "Khóa riêng RSA của B (PEM)": cert.get("server_private_key_pem"),
                "Đệm RSA": "PKCS#1 v1.5",
            }
            outputs = {
                "Bí mật tiền chủ của B (hex)": d.get("premaster_secret"),
                "Khớp bí mật phía A": d.get("matches_A"),
            }
        elif title == "B ký khóa tạm thời":
            inputs = {
                "Phương pháp trao đổi khóa": d.get("exchange"),
                "Kiểu chữ ký": d.get("authentication"),
                "Khóa riêng ký của B (PEM)": cert.get("server_private_key_pem"),
                "Client random (hex)": d.get("client_random"),
                "Server random (hex)": d.get("server_random"),
                "Dữ liệu được ký (hex)": d.get("signed_data"),
                "Nguồn tạo khóa tạm thời": "Bộ sinh số ngẫu nhiên của hệ điều hành",
            }
            outputs = {
                "Khóa công khai tạm thời của A (hex)": d.get("A_public_key"),
                "Khóa riêng tạm thời của A (PEM)": d.get("A_ephemeral_private_key_pem"),
                "Khóa công khai tạm thời của B (hex)": d.get("B_public_key"),
                "Khóa riêng tạm thời của B (PEM)": d.get("B_ephemeral_private_key_pem"),
                "Chữ ký trên random và khóa B (hex)": d.get("signature"),
                "Hash chữ ký": d.get("signature_hash"),
            }
        elif title == "Kiểm tra chữ ký và tính bí mật chung":
            inputs = {
                "Khóa công khai xác thực của B (PEM)": cert.get(
                    "server_public_key_pem"
                ),
                "Chữ ký (hex)": exchange.get("signature"),
                "Client random (hex)": exchange.get("client_random"),
                "Server random (hex)": exchange.get("server_random"),
                "Khóa công khai tạm thời của A (hex)": exchange.get("A_public_key"),
                "Khóa công khai tạm thời của B (hex)": exchange.get("B_public_key"),
                "Khóa riêng tạm thời của A (PEM)": exchange.get(
                    "A_ephemeral_private_key_pem"
                ),
                "Khóa riêng tạm thời của B (PEM)": exchange.get(
                    "B_ephemeral_private_key_pem"
                ),
            }
            outputs = {
                "Xác minh chữ ký": d.get("signature"),
                "Bí mật chung của A (hex)": d.get("A_shared_secret"),
                "Bí mật chung của B (hex)": d.get("B_shared_secret"),
                "Hai bí mật khớp": d.get("matches"),
            }
        elif title == "Dẫn xuất khóa phiên độc lập":
            inputs = {
                "Hàm dẫn xuất": d.get("algorithm"),
                "Hash": d.get("hash"),
                "Bí mật đầu vào phía A (hex)": shared.get(
                    "A_shared_secret", exchange.get("premaster_secret")
                ),
                "Bí mật đầu vào phía B (hex)": shared.get(
                    "B_shared_secret",
                    by_title.get("RSA giải mã bí mật tiền chủ", {}).get(
                        "premaster_secret"
                    ),
                ),
                "Client random (hex)": exchange.get("client_random"),
                "Server random (hex)": exchange.get("server_random"),
            }
            random_a = bytes.fromhex(exchange["client_random"])
            random_b = bytes.fromhex(exchange["server_random"])
            if config["version"] == "TLS 1.2":
                inputs["PRF seed tạo master secret (hex)"] = (
                    b"master secret" + random_a + random_b
                ).hex()
                inputs["PRF seed mở rộng khóa (hex)"] = (
                    b"key expansion" + random_b + random_a
                ).hex()
            else:
                digest = (
                    hashlib.sha256
                    if config["hash_name"] == "SHA-256"
                    else hashlib.sha384
                )
                inputs["HKDF salt (hex)"] = digest(random_a + random_b).hexdigest()
                inputs["HKDF info (UTF-8)"] = "educational tls13-like A->B key"
            outputs = {
                "Master secret A (hex)": d.get("master_secret_A"),
                "Master secret B (hex)": d.get("master_secret_B"),
                "Khóa A → B phía A (hex)": d.get("A_to_B_key_A"),
                "Khóa A → B phía B (hex)": d.get("A_to_B_key_B"),
                "Hai khóa khớp": d.get("keys_match"),
            }
        elif title == "AES-GCM mã hóa và tạo tag":
            inputs = {
                "Thông điệp (UTF-8)": d.get("plaintext_utf8"),
                "Bản rõ (hex)": d.get("plaintext_hex"),
                "Khóa AES phía A (hex)": key_step.get("A_to_B_key_A"),
                "Nonce (hex)": d.get("nonce"),
                "AAD (UTF-8)": d.get("aad_utf8"),
                "Thuật toán": config["cipher"],
            }
            outputs = {
                "Bản mã (hex)": d.get("ciphertext_hex"),
                "Tag xác thực (hex)": d.get("tag_hex"),
                "Độ dài bản mã (byte)": d.get("ciphertext_bytes"),
                "Độ dài tag (byte)": d.get("tag_bytes"),
            }
        elif title == "Truyền bản mã qua TCP loopback":
            inputs = {
                "Địa chỉ": d.get("address"),
                "Nonce (hex)": enc.get("nonce"),
                "Bản mã trước khi truyền (hex)": enc.get("ciphertext_hex"),
                "Tag gốc (hex)": enc.get("tag_hex"),
                "Yêu cầu sửa tag": d.get("tampered"),
            }
            outputs = {
                "Khung sau khi truyền (hex)": d.get("frame_hex"),
                "Độ dài khung (byte)": d.get("frame_bytes"),
                "Giới hạn": d.get("note"),
            }
        elif title == "Kiểm tra tag và giải mã":
            frame = bytes.fromhex(model_wire["frame_hex"])
            packet = frame[4:]
            inputs = {
                "Khóa AES phía B (hex)": key_step.get("A_to_B_key_B"),
                "Nonce nhận được (hex)": packet[:12].hex(),
                "Bản mã nhận được (hex)": packet[12:-16].hex(),
                "Tag nhận được (hex)": packet[-16:].hex(),
                "AAD (UTF-8)": enc.get("aad_utf8"),
            }
            outputs = {
                "Kết quả kiểm tra tag": d.get("tag"),
                "Bản rõ nhận được (UTF-8)": d.get("plaintext_utf8"),
                "Bản rõ (hex)": d.get("plaintext_hex"),
                "Khớp thông điệp ban đầu": d.get("matches_original"),
                "Thông báo": d.get("result"),
            }
        elif title == "Chuẩn bị thông điệp gửi B":
            inputs = {"Thông điệp A nhập (UTF-8)": d.get("plaintext_utf8")}
            outputs = {
                "Nội dung HTTP A chuẩn bị (UTF-8)": d.get("plaintext_utf8"),
                "Độ dài nội dung (byte)": d.get("plaintext_bytes"),
                "SHA-256 nội dung": d.get("plaintext_sha256"),
            }
        elif title == "Truyền dữ liệu SSL qua loopback":
            inputs = {
                "Chiều truyền": step["actor"],
                "Đoạn TCP proxy nhận (hex)": d.get("wire_hex"),
            }
            outputs = {
                "Đoạn TCP đã chuyển tiếp (hex)": d.get("wire_hex"),
                "Số byte chuyển tiếp": d.get("wire_bytes"),
                "Phạm vi": "Đoạn TCP có thể gồm một phần hoặc nhiều SSL/TLS record.",
            }
        elif title.startswith("Gửi bản ghi handshake từ"):
            inputs = {
                "Chiều truyền": step["actor"],
                "TLS record đầu vào (hex)": d.get("wire_hex"),
            }
            outputs = {
                "TLS record đã chuyển tiếp (hex)": d.get("wire_hex"),
                "Số byte": d.get("bytes"),
                "Cấu trúc record quan sát được": d.get("records"),
            }
        elif title == "Handshake TLS hoàn tất":
            inputs = {
                "Phiên bản yêu cầu": config["version"],
                "Trao đổi khóa yêu cầu": config["exchange"],
                "Xác thực yêu cầu": config["authentication"],
                "Mã hóa yêu cầu": config["cipher"],
                "Chứng chỉ CA (PEM)": cert.get("ca_certificate_pem"),
                "Khóa riêng chứng chỉ B (PEM)": cert.get("server_private_key_pem"),
                "Hostname cần xác minh": "B.local",
            }
            outputs = {
                "Phiên bản thực tế": d.get("version"),
                "Cipher suite thực tế": d.get("cipher"),
                "Nhóm khóa thực tế": d.get("observed_group")
                if config["exchange"] != "RSA key transport"
                else "RSA key transport; không có nhóm DH",
                "Loại khóa chứng chỉ": d.get("authentication"),
                "Chứng chỉ hợp lệ": d.get("certificate_verified"),
                "Khóa phiên": hidden,
            }
            if config["exchange"] != "RSA key transport":
                outputs["Khóa riêng DH/ECDHE tạm thời"] = hidden_ephemeral
        elif title == "Mã hóa thành TLS application record":
            inputs = {
                "Thông điệp (UTF-8)": d.get("plaintext_utf8"),
                "Độ dài bản rõ (byte)": d.get("plaintext_bytes"),
                "Cipher suite": config["cipher"],
                "Khóa phiên": hidden,
                "Nonce và AAD đầy đủ": hidden_nonce,
            }
            outputs = {
                "TLS application record (hex)": d.get("tls_record_hex"),
                "Độ dài record (byte)": d.get("tls_record_bytes"),
                "Loại record": d.get("record_type"),
            }
            record = bytes.fromhex(d["tls_record_hex"])
            if (
                len(record) >= 21
                and record[0] == 23
                and len(record) == 5 + int.from_bytes(record[3:5], "big")
            ):
                if config["version"] == "TLS 1.2" and len(record) >= 29:
                    outputs["Nonce tường minh của record (hex)"] = record[5:13].hex()
                    outputs["Bản mã TLS (hex)"] = record[13:-16].hex()
                elif config["version"] == "TLS 1.3":
                    outputs["Bản mã TLS 1.3, gồm kiểu nội dung bên trong (hex)"] = (
                        record[5:-16].hex()
                    )
                outputs["Tag xác thực GCM (hex)"] = record[-16:].hex()
        elif title == "Truyền TLS record qua TCP loopback":
            inputs = {
                "TLS record trước khi truyền (hex)": real_enc.get("tls_record_hex"),
                "Địa chỉ": "127.0.0.1",
                "Yêu cầu sửa bản ghi": d.get("tampered"),
            }
            outputs = {
                "TLS record sau khi truyền (hex)": d.get("wire_hex"),
                "Số byte": d.get("wire_bytes"),
            }
        elif title == "Xác thực và giải mã TLS record":
            inputs = {
                "TLS record nhận được (hex)": real_wire.get("wire_hex"),
                "Khóa phiên": hidden,
                "Nonce và AAD đầy đủ": hidden_nonce,
            }
            outputs = {
                "Kết quả xác thực": d.get("tag"),
                "Thông điệp nhận (UTF-8)": d.get("plaintext_utf8"),
                "Khớp thông điệp ban đầu": d.get("matches_original"),
                "Lỗi từ OpenSSL": d.get("error"),
            }
        elif title == "Xác minh chứng chỉ và nhận thông điệp":
            inputs = {
                "Dữ liệu đầu vào": "Các đoạn SSL/TLS đã chuyển tiếp trong những bước trước",
                "Chứng chỉ được tin cậy (PEM)": cert.get("certificate_pem"),
                "Hostname cần xác minh": "localhost",
            }
            outputs = {
                "Phiên bản thực tế": d.get("observed_protocol"),
                "Cipher suite thực tế": d.get("suite"),
                "Nhóm khóa thực tế": d.get("observed_group")
                if config["exchange"] != "RSA key transport"
                else "RSA key transport; không có nhóm DH",
                "Loại khóa chứng chỉ": d.get("authentication"),
                "Xác minh chứng chỉ": d.get("verify_return"),
                "Thông điệp nhận (UTF-8)": d.get("plaintext_utf8"),
                "Khớp thông điệp ban đầu": d.get("matches_original"),
            }
            if config["exchange"] != "RSA key transport":
                outputs["Khóa riêng DH/ECDHE tạm thời"] = (
                    "OpenSSL CLI không xuất khóa riêng tạm thời trong phép thử này."
                )
        else:
            inputs = {"Đầu vào": "Không được ghi lại cho bước này."}
            outputs = {"Thông tin thu được": d}
        step["inputs"] = inputs
        step["outputs"] = outputs
        if result.get("mode") == "real":
            methods = {
                "Chuẩn bị khóa và chứng chỉ": "rsa.generate_private_key hoặc ec.generate_private_key sinh khóa; x509.CertificateBuilder.sign ký chứng chỉ bằng khóa CA. OpenSSL nạp chứng chỉ và khóa qua SSLContext.load_cert_chain.",
                "Handshake TLS hoàn tất": "SSLObject.do_handshake chạy handshake và kiểm tra chứng chỉ/hostname qua OpenSSL. API ssl không xuất từng phép trao đổi khóa, chữ ký và dẫn xuất khóa cùng các giá trị trung gian.",
                "Mã hóa thành TLS application record": "SSLObject.write đưa bản rõ vào OpenSSL; OpenSSL tạo TLS record theo cipher suite đã thương lượng. API ssl không xuất khóa phiên, nonce đầy đủ và AAD.",
                "Truyền TLS record qua TCP loopback": "socket.sendall gửi record; _read_exact nhận đủ byte; MemoryBIO.write chuyển byte đến OpenSSL. Nếu bật sửa bản ghi, byte cuối được XOR với 1 trước khi gửi.",
                "Xác thực và giải mã TLS record": "SSLObject.read gọi OpenSSL xác thực và giải mã record; khi xác thực lỗi, OpenSSL phát sinh SSLError và không trả bản rõ.",
            }
            if title.startswith("Gửi bản ghi handshake từ"):
                step["method"] = (
                    "MemoryBIO.read lấy byte từ OpenSSL; socket.sendall và _read_exact truyền qua TCP loopback; MemoryBIO.write đưa byte tới đầu kia. Các byte này có thể gồm nhiều record."
                )
            elif title in methods:
                step["method"] = methods[title]
    return result
