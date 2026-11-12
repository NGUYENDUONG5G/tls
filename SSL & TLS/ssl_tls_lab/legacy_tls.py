"""Isolated real SSL 2.0–TLS 1.1 message exchange using the legacy image."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .message_demo import DemoConfig


def run_legacy_tls(message: str, config: DemoConfig, tamper: bool = False) -> dict:
    config.validate()
    if config.version not in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
        raise ValueError("Backend cũ chỉ hỗ trợ SSL 2.0/3.0 và TLS 1.0/1.1.")
    if tamper:
        raise ValueError(
            "Chưa hỗ trợ sửa record trên backend cũ; bỏ tùy chọn sửa bản ghi để chạy."
        )
    payload = message.encode("utf-8")
    if not 1 <= len(payload) <= 16000:
        raise ValueError("Thông điệp cần 1–16000 byte UTF-8.")
    if config.version.startswith("TLS"):
        prefix = (
            f"ECDHE-{'ECDSA' if config.authentication.startswith('ECDSA') else 'RSA'}-"
            if config.exchange == "ECDHE P-256"
            else "DHE-RSA-"
            if config.exchange == "DHE 2048"
            else ""
        )
        cipher = prefix + (
            "AES128-SHA" if config.cipher == "AES-128-CBC" else "AES256-SHA"
        )
    else:
        cipher = {
            "RC4-128": "RC4-MD5",
            "3DES-CBC": "DES-CBC3-MD5"
            if config.version == "SSL 2.0"
            else "DES-CBC3-SHA",
        }[config.cipher]
    worker = Path(__file__).resolve().parent / "legacy_message_worker.py"
    name = "ssl-message-" + uuid.uuid4().hex[:16]
    args = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        f"type=bind,src={worker},dst=/worker.py,readonly",
        "--entrypoint",
        "python",
        "ssl-tls-lab:legacy",
        "/worker.py",
    ]
    req = {
        "version": config.version,
        "cipher": cipher,
        "authentication": config.authentication,
        "rsa_bits": config.rsa_bits,
        "message_base64": base64.b64encode(payload).decode(),
    }
    if config.exchange == "DHE 2048":
        from .dh_group import pem

        req["dh_pem"] = pem().decode("ascii")
    try:
        process = subprocess.run(
            args, input=json.dumps(req), capture_output=True, text=True, timeout=55
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Thiếu Docker. Cài Docker và build image ssl-tls-lab:legacy theo README."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        subprocess.run(
            ["docker", "rm", "-f", name], capture_output=True, timeout=10, check=False
        )
        raise RuntimeError("Lab SSL cũ hết thời gian chờ.") from exc
    try:
        response = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Không chạy được container legacy: "
            + (process.stderr[-1500:] or process.stdout[-1500:])
        ) from exc
    if not response.get("ok"):
        raise RuntimeError(response.get("error") or process.stderr[-1500:])
    raw = response["result"]
    received = base64.b64decode(raw["message_base64"], validate=True)
    if received != payload:
        raise RuntimeError("Nội dung nhận không khớp.")
    cert = x509.load_pem_x509_certificate(raw["cert_pem"].encode())
    public = cert.public_key()
    private = serialization.load_pem_private_key(
        raw["server_private_key_pem"].encode(), password=None
    )
    public_der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if (
        private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        != public_der
    ):
        raise RuntimeError("Khóa riêng không khớp chứng chỉ server.")
    auth = (
        "RSA"
        if isinstance(public, rsa.RSAPublicKey)
        else "ECDSA P-256"
        if isinstance(public, ec.EllipticCurvePublicKey)
        and isinstance(public.curve, ec.SECP256R1)
        else "unknown"
    )
    if auth != config.authentication:
        raise RuntimeError(
            f"Loại khóa chứng chỉ thực tế {auth} khác yêu cầu {config.authentication}."
        )
    group = None
    if config.exchange != "RSA key transport":
        from .real_tls import negotiated_group

        group = negotiated_group(
            [
                bytes.fromhex(x["wire_hex"])
                for x in raw["captures"]
                if x["direction"] == "A → B"
            ],
            "TLS 1.2",
        )
        if group != config.exchange:
            raise RuntimeError(
                f"Không xác minh được nhóm trao đổi khóa: yêu cầu {config.exchange}, quan sát {group}."
            )
    cert_size = len(cert.public_bytes(serialization.Encoding.DER))
    steps = [
        {
            "index": 1,
            "actor": "A / CA",
            "title": "Chuẩn bị server và chứng chỉ",
            "duration_ms": raw["prep_ms"],
            "offset_ms": raw["prep_ms"],
            "description": "Tạo chứng chỉ thử nghiệm trong container cô lập.",
            "details": {
                "openssl": raw["openssl"],
                "certificate_bytes": cert_size,
                "certificate_pem": raw["cert_pem"],
                "server_public_key_pem": public.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode(),
                "server_private_key_pem": raw["server_private_key_pem"],
                "requested_protocol": config.version,
                "requested_cipher": cipher,
                "network": raw["network"],
            },
        }
    ]
    steps.append(
        {
            "index": 2,
            "actor": "A",
            "title": "Chuẩn bị thông điệp gửi B",
            "duration_ms": None,
            "offset_ms": None,
            "description": "A đặt thông điệp trong nội dung HTTP; B tải nội dung qua phiên SSL/TLS.",
            "details": {
                "plaintext_utf8": message,
                "plaintext_bytes": len(payload),
                "plaintext_sha256": hashlib.sha256(payload).hexdigest(),
            },
        }
    )
    for capture in raw["captures"]:
        steps.append(
            {
                "index": len(steps) + 1,
                "actor": capture["direction"],
                "title": "Truyền dữ liệu SSL qua loopback",
                "duration_ms": None,
                "offset_ms": capture["offset_ms"],
                "description": "Một đoạn byte thực trên TCP; đoạn TCP có thể chứa một phần hoặc nhiều SSL record.",
                "details": {
                    "wire_bytes": capture["bytes"],
                    "wire_hex": capture["wire_hex"],
                },
            }
        )
    steps.append(
        {
            "index": len(steps) + 1,
            "actor": "B",
            "title": "Xác minh chứng chỉ và nhận thông điệp",
            "duration_ms": None,
            "offset_ms": raw["total_ms"],
            "description": "B kiểm tra chứng chỉ/hostname và nhận đúng nội dung HTTP qua phiên SSL/TLS. Phiên bản và cipher được đọc từ chính output client; nhóm được kiểm tra trong ServerKeyExchange.",
            "details": {
                "plaintext_utf8": message,
                "matches_original": True,
                "openssl_log": raw["client_stderr"],
                "suite": raw["observed_cipher"],
                "protocol": config.version,
                "observed_protocol": raw["observed_protocol"],
                "observed_group": group,
                "authentication": auth,
                "verify_return": raw["verify_return"],
            },
        }
    )
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": f"{config.version} thực trong container OpenSSL 1.0.2u",
        "config": asdict(config),
        "status": "success",
        "tampered": False,
        "input": message,
        "output": message,
        "steps": steps,
        "metrics": {
            "total_ms": raw["total_ms"],
            "process_cpu_ms": None,
            "setup_ms": raw["prep_ms"],
            "handshake_ms": None,
            "handshake_bytes": None,
            "encrypt_ms": None,
            "tcp_loopback_ms": None,
            "tcp_frame_mib_s": None,
            "decrypt_verify_ms": None,
            "plaintext_bytes": len(payload),
            "ciphertext_bytes": None,
            "tag_bytes": None,
            "nonce_bytes": None,
            "frame_bytes": None,
            "wire_overhead_bytes": None,
            "certificate_bytes": cert_size,
            "end_to_end_ms": raw["transfer_elapsed_ms"],
            "captured_wire_bytes": sum(x["bytes"] for x in raw["captures"]),
        },
        "limitations": [
            "Log chứa khóa riêng server của phiên thí nghiệm; không dùng khóa này cho dữ liệu thật.",
            "A là server trả dữ liệu HTTP, B là client; các byte chụp được gồm handshake, HTTP và dữ liệu ứng dụng.",
            "Không tách được độ trễ handshake, mã hóa và truyền từ phép đo tiến trình; các metric đó để null.",
            "Thời gian được đo trong container, không gồm khởi động Docker.",
            "Backend giao thức cũ chỉ chạy trong container network none; không dùng ngoài lab.",
            "Chưa hỗ trợ sửa tag/bản ghi với backend cũ.",
        ],
    }
