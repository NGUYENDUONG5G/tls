"""Attach observable inputs and outputs to each legacy-backend step."""

from __future__ import annotations

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
    """Inputs and outputs of each step recorded by the legacy backend."""
    config = result["config"]
    cert = next(
        (s["details"] for s in result["steps"] if s["title"] == "Chuẩn bị server và chứng chỉ"),
        {},
    )
    for step in result["steps"]:
        title = step["title"]
        d = step["details"]
        if title == "Chuẩn bị server và chứng chỉ":
            inputs = {
                "Phiên bản": config["version"],
                "Xác thực server": config["authentication"],
                "Thuật toán trao đổi khóa": config["exchange"],
                "Mã hóa": config["cipher"],
            }
            if config["authentication"] == "RSA":
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
            if d.get("server_private_key_pem"):
                operations = rsa_key_operations(d["server_private_key_pem"], "server")
                if operations:
                    step["operations"] = operations
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
    return result
