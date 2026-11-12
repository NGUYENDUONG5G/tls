"""Observable cryptographic message exchange for teaching; not a TLS stack."""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class DemoConfig:
    version: str = "TLS 1.2"
    exchange: str = "RSA key transport"
    authentication: str = "RSA"
    cipher: str = "AES-128-GCM"
    hash_name: str = "SHA-256"
    rsa_bits: int = 2048

    def validate(self):
        if self.version == "SSL 1.0":
            raise ValueError(
                "SSL 1.0 chỉ có dữ liệu lịch sử; chưa có triển khai công khai được xác minh để chạy."
            )
        if self.version not in (
            "SSL 2.0",
            "SSL 3.0",
            "TLS 1.0",
            "TLS 1.1",
            "TLS 1.2",
            "TLS 1.3",
        ):
            raise ValueError("Phiên bản không được hỗ trợ.")
        if self.exchange not in (
            "RSA key transport",
            "DHE 2048",
            "DHE ffdhe2048",
            "ECDHE X25519",
            "ECDHE P-256",
        ):
            raise ValueError("Phương thức trao đổi khóa không được hỗ trợ.")
        if self.version == "TLS 1.3" and self.exchange not in (
            "ECDHE X25519",
            "ECDHE P-256",
            "DHE ffdhe2048",
        ):
            raise ValueError(
                "TLS 1.3 hỗ trợ ECDHE X25519/P-256 hoặc DHE ffdhe2048 trong ứng dụng."
            )
        if self.authentication not in ("RSA", "ECDSA P-256") or self.rsa_bits not in (
            2048,
            3072,
        ):
            raise ValueError("Xác thực hoặc kích thước khóa RSA không hợp lệ.")
        if self.authentication == "ECDSA P-256" and (
            self.version not in ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
            or (self.version != "TLS 1.3" and not self.exchange.startswith("ECDHE"))
        ):
            raise ValueError(
                "ECDSA P-256 yêu cầu ECDHE trên TLS 1.0–1.2 hoặc ECDHE/DHE trên TLS 1.3."
            )
        suites = {
            "SSL 2.0": {("RC4-128", "MD5"), ("3DES-CBC", "MD5")},
            "SSL 3.0": {("RC4-128", "MD5"), ("3DES-CBC", "SHA-1")},
            "TLS 1.0": {("AES-128-CBC", "SHA-1"), ("AES-256-CBC", "SHA-1")},
            "TLS 1.1": {("AES-128-CBC", "SHA-1"), ("AES-256-CBC", "SHA-1")},
            "TLS 1.2": {("AES-128-GCM", "SHA-256"), ("AES-256-GCM", "SHA-384")},
            "TLS 1.3": {("AES-128-GCM", "SHA-256"), ("AES-256-GCM", "SHA-384")},
        }
        exchanges = {
            "SSL 2.0": {"RSA key transport"},
            "SSL 3.0": {"RSA key transport"},
            "TLS 1.0": {"RSA key transport", "DHE 2048", "ECDHE P-256"},
            "TLS 1.1": {"RSA key transport", "DHE 2048", "ECDHE P-256"},
            "TLS 1.2": {"RSA key transport", "DHE 2048", "ECDHE X25519", "ECDHE P-256"},
            "TLS 1.3": {"ECDHE X25519", "ECDHE P-256", "DHE ffdhe2048"},
        }
        if (self.cipher, self.hash_name) not in suites[
            self.version
        ] or self.exchange not in exchanges[self.version]:
            raise ValueError(
                "Tổ hợp trao đổi khóa, mã hóa và hash không được hỗ trợ cho phiên bản này."
            )


def p_hash(secret: bytes, seed: bytes, length: int, digest) -> bytes:
    """TLS 1.2 P_hash: HMAC(secret,A(i)||seed), A(1)=HMAC(secret,seed)."""
    result = b""
    a = seed
    while len(result) < length:
        a = hmac.new(secret, a, digest).digest()
        result += hmac.new(secret, a + seed, digest).digest()
    return result[:length]


def _read_exact(sock, length):
    chunks = []
    while length:
        part = sock.recv(length)
        if not part:
            raise ConnectionError("Kết nối đóng trước khi nhận đủ dữ liệu")
        chunks.append(part)
        length -= len(part)
    return b"".join(chunks)


def run_message(message: str, config: DemoConfig, tamper: bool = False) -> dict:
    config.validate()
    if config.version not in ("TLS 1.2", "TLS 1.3"):
        raise ValueError(
            "Mô hình từng bước chỉ hỗ trợ TLS 1.2/1.3; chọn chế độ kết nối thực cho phiên bản cũ."
        )
    plaintext = message.encode("utf-8")
    if not plaintext or len(plaintext) > 32768:
        raise ValueError("Nhập thông điệp từ 1 đến 32768 byte UTF-8.")
    start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    steps = []

    def step(actor, title, started, details):
        finished = time.perf_counter_ns()
        steps.append(
            {
                "index": len(steps) + 1,
                "actor": actor,
                "title": title,
                "duration_ms": (finished - started) / 1_000_000,
                "offset_ms": (finished - start) / 1_000_000,
                "details": details,
            }
        )

    hash_alg = hashes.SHA256() if config.hash_name == "SHA-256" else hashes.SHA384()
    digest = hashlib.sha256 if config.hash_name == "SHA-256" else hashlib.sha384
    key_bytes = 16 if config.cipher == "AES-128-GCM" else 32

    t = time.perf_counter_ns()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=config.rsa_bits)
    server_key = (
        rsa.generate_private_key(public_exponent=65537, key_size=config.rsa_bits)
        if config.authentication == "RSA"
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA Minh hoa TLS")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "B.local")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hash_alg)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("B.local")]), False)
        .sign(ca_key, hash_alg)
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    private_format = lambda key: key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    step(
        "B / CA",
        "Tạo khóa và chứng chỉ thử nghiệm",
        t,
        {
            "authentication": config.authentication,
            "certificate_key_bits": server_key.key_size,
            "rsa_ca_bits": config.rsa_bits,
            "certificate_bytes": len(cert_der),
            "subject": "B.local",
            "certificate_sha256": hashlib.sha256(cert_der).hexdigest(),
            "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_certificate_pem": ca_cert.public_bytes(
                serialization.Encoding.PEM
            ).decode(),
            "server_public_key_pem": server_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode(),
            "server_private_key_pem": private_format(server_key),
            "ca_private_key_pem": private_format(ca_key),
            "note": "CA RSA ký chứng chỉ server được tạo cho lần minh họa này.",
        },
    )

    t = time.perf_counter_ns()
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    if (
        cert.issuer != ca_cert.subject
        or "B.local"
        not in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    ):
        raise ValueError("Tên hoặc CA của chứng chỉ không hợp lệ")
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Chứng chỉ ngoài thời hạn")
    step(
        "A",
        "Kiểm tra chứng chỉ của B",
        t,
        {
            "signature": "hợp lệ",
            "issuer": "CA Minh hoa TLS",
            "hostname": "B.local",
            "validity": "hợp lệ",
            "note": "Kiểm tra minh họa: chữ ký CA, issuer, SAN và thời hạn; chưa xây dựng chuỗi tổng quát hoặc kiểm tra thu hồi.",
        },
    )

    client_random, server_random = os.urandom(32), os.urandom(32)
    if config.exchange == "RSA key transport":
        t = time.perf_counter_ns()
        secret_a = b"\x03\x03" + os.urandom(46)
        encrypted_secret = cert.public_key().encrypt(secret_a, padding.PKCS1v15())
        step(
            "A → B",
            "RSA mã hóa bí mật tiền chủ",
            t,
            {
                "client_random": client_random.hex(),
                "server_random": server_random.hex(),
                "premaster_secret": secret_a.hex(),
                "rsa_ciphertext": encrypted_secret.hex(),
                "rsa_ciphertext_bytes": len(encrypted_secret),
            },
        )
        t = time.perf_counter_ns()
        secret_b = server_key.decrypt(encrypted_secret, padding.PKCS1v15())
        step(
            "B",
            "RSA giải mã bí mật tiền chủ",
            t,
            {"premaster_secret": secret_b.hex(), "matches_A": secret_a == secret_b},
        )
    else:
        t = time.perf_counter_ns()
        if config.exchange == "ECDHE X25519":
            a_key, b_key = (
                x25519.X25519PrivateKey.generate(),
                x25519.X25519PrivateKey.generate(),
            )
            a_public = a_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            b_public = b_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            public_a = x25519.X25519PublicKey.from_public_bytes(a_public)
            public_b = x25519.X25519PublicKey.from_public_bytes(b_public)
        elif config.exchange == "ECDHE P-256":
            a_key, b_key = (
                ec.generate_private_key(ec.SECP256R1()),
                ec.generate_private_key(ec.SECP256R1()),
            )
            a_public = a_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            b_public = b_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            public_a = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), a_public
            )
            public_b = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b_public
            )
        else:
            from .dh_group import parameters, ffdhe_parameters

            group = (
                ffdhe_parameters()
                if config.exchange == "DHE ffdhe2048"
                else parameters()
            )
            a_key, b_key = group.generate_private_key(), group.generate_private_key()
            a_public = a_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            b_public = b_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_a = serialization.load_der_public_key(a_public)
            public_b = serialization.load_der_public_key(b_public)
        signed = client_random + server_random + b_public
        sig_hash = hash_alg if config.authentication == "RSA" else hashes.SHA256()
        if config.authentication == "RSA":
            signature = server_key.sign(
                signed,
                padding.PSS(
                    mgf=padding.MGF1(sig_hash), salt_length=sig_hash.digest_size
                ),
                sig_hash,
            )
        else:
            signature = server_key.sign(signed, ec.ECDSA(sig_hash))
        step(
            "B → A",
            "B ký khóa tạm thời",
            t,
            {
                "exchange": config.exchange,
                "authentication": config.authentication,
                "client_random": client_random.hex(),
                "server_random": server_random.hex(),
                "A_public_key": a_public.hex(),
                "B_public_key": b_public.hex(),
                "A_ephemeral_private_key_pem": private_format(a_key),
                "B_ephemeral_private_key_pem": private_format(b_key),
                "signed_data": signed.hex(),
                "signature": signature.hex(),
                "signature_bytes": len(signature),
                "signature_hash": sig_hash.name,
            },
        )
        t = time.perf_counter_ns()
        if config.authentication == "RSA":
            cert.public_key().verify(
                signature,
                signed,
                padding.PSS(
                    mgf=padding.MGF1(sig_hash), salt_length=sig_hash.digest_size
                ),
                sig_hash,
            )
        else:
            cert.public_key().verify(signature, signed, ec.ECDSA(sig_hash))
        if config.exchange == "ECDHE P-256":
            secret_a = a_key.exchange(ec.ECDH(), public_b)
            secret_b = b_key.exchange(ec.ECDH(), public_a)
        else:
            secret_a = a_key.exchange(public_b)
            secret_b = b_key.exchange(public_a)
        step(
            "A ↔ B",
            "Kiểm tra chữ ký và tính bí mật chung",
            t,
            {
                "signature": "hợp lệ",
                "exchange": config.exchange,
                "A_shared_secret": secret_a.hex(),
                "B_shared_secret": secret_b.hex(),
                "matches": secret_a == secret_b,
            },
        )
    if not hmac.compare_digest(secret_a, secret_b):
        raise ValueError("Bí mật của A và B không khớp")

    def derive(secret):
        if config.version == "TLS 1.2":
            master = p_hash(
                secret, b"master secret" + client_random + server_random, 48, digest
            )
            material = p_hash(
                master,
                b"key expansion" + server_random + client_random,
                2 * key_bytes + 8,
                digest,
            )
            return (
                master,
                material[:key_bytes],
                "TLS 1.2 PRF P_hash (không dùng extended master secret)",
            )
        salt = digest(client_random + server_random).digest()
        material = HKDF(
            algorithm=hash_alg,
            length=key_bytes,
            salt=salt,
            info=b"educational tls13-like A->B key",
        ).derive(secret)
        return None, material, "HKDF minh họa; không phải TLS 1.3 key schedule"

    t = time.perf_counter_ns()
    master_a, key_a, kdf_name = derive(secret_a)
    master_b, key_b, _ = derive(secret_b)
    step(
        "A ↔ B",
        "Dẫn xuất khóa phiên độc lập",
        t,
        {
            "algorithm": kdf_name,
            "hash": config.hash_name,
            "master_secret_A": master_a.hex() if master_a else None,
            "master_secret_B": master_b.hex() if master_b else None,
            "A_to_B_key_A": key_a.hex(),
            "A_to_B_key_B": key_b.hex(),
            "keys_match": hmac.compare_digest(key_a, key_b),
        },
    )

    t = time.perf_counter_ns()
    nonce = os.urandom(12)
    aad = f"DEMO|{config.version}|{config.exchange}|{config.authentication}|{config.cipher}|{config.hash_name}".encode()
    encrypted = AESGCM(key_a).encrypt(nonce, plaintext, aad)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    step(
        "A",
        "AES-GCM mã hóa và tạo tag",
        t,
        {
            "plaintext_utf8": message,
            "plaintext_hex": plaintext.hex(),
            "nonce": nonce.hex(),
            "aad_utf8": aad.decode(),
            "ciphertext_hex": ciphertext.hex(),
            "tag_hex": tag.hex(),
            "plaintext_bytes": len(plaintext),
            "ciphertext_bytes": len(ciphertext),
            "tag_bytes": len(tag),
        },
    )

    t = time.perf_counter_ns()
    packet = nonce + encrypted
    if tamper:
        packet = packet[:-1] + bytes([packet[-1] ^ 1])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=5) as a:
            with listener.accept()[0] as b:
                b.settimeout(5)
                framed = struct.pack("!I", len(packet)) + packet
                a.sendall(framed)
                size = struct.unpack("!I", _read_exact(b, 4))[0]
                received = _read_exact(b, size)
    step(
        "A → B",
        "Truyền bản mã qua TCP loopback",
        t,
        {
            "address": "127.0.0.1",
            "frame_hex": framed.hex(),
            "frame_bytes": len(framed),
            "length_prefix_bytes": 4,
            "nonce_bytes": 12,
            "ciphertext_bytes": len(ciphertext),
            "tag_bytes": 16,
            "tampered": tamper,
            "note": "Khung demo tự định nghĩa; không phải TLS record. Đo gồm tạo socket và truyền loopback.",
        },
    )
    t = time.perf_counter_ns()
    try:
        decrypted = AESGCM(key_b).decrypt(received[:12], received[12:], aad)
        status = "success"
        output = decrypted.decode("utf-8")
        details = {
            "tag": "hợp lệ",
            "plaintext_utf8": output,
            "plaintext_hex": decrypted.hex(),
            "matches_original": decrypted == plaintext,
        }
    except InvalidTag:
        status, output = "rejected", None
        details = {
            "tag": "không hợp lệ",
            "plaintext_utf8": None,
            "result": "B từ chối bản ghi; không trả bản rõ.",
        }
    step("B", "Kiểm tra tag và giải mã", t, details)
    elapsed = (time.perf_counter_ns() - start) / 1_000_000
    cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000
    by_title = {s["title"]: s["duration_ms"] for s in steps}
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": "Minh họa lấy cảm hứng TLS; không tương thích giao thức TLS thật",
        "config": asdict(config),
        "status": status,
        "tampered": tamper,
        "input": message,
        "output": output,
        "steps": steps,
        "metrics": {
            "total_ms": elapsed,
            "process_cpu_ms": cpu_ms,
            "setup_ms": sum(s["duration_ms"] for s in steps[:5]),
            "encrypt_ms": by_title["AES-GCM mã hóa và tạo tag"],
            "tcp_loopback_ms": by_title["Truyền bản mã qua TCP loopback"],
            "tcp_frame_mib_s": len(framed)
            / (1024**2)
            / (by_title["Truyền bản mã qua TCP loopback"] / 1000),
            "decrypt_verify_ms": by_title["Kiểm tra tag và giải mã"],
            "plaintext_bytes": len(plaintext),
            "ciphertext_bytes": len(ciphertext),
            "tag_bytes": 16,
            "nonce_bytes": 12,
            "frame_bytes": len(framed),
            "wire_overhead_bytes": len(framed) - len(plaintext),
            "certificate_bytes": len(cert_der),
        },
        "limitations": [
            "Các bước handshake được mô phỏng trong một tiến trình; chỉ bản mã được truyền qua TCP loopback.",
            "Khung dữ liệu không tương thích TLS; đây không phải triển khai hay phép đo TLS thực.",
            "TLS 1.3 dùng HKDF minh họa, không triển khai đầy đủ TLS 1.3 key schedule/Finished.",
            "CPU là tổng CPU của tiến trình A và B, gồm cả các luồng khác; tốc độ khung dựa trên một lần gồm tạo socket, không đại diện thông lượng mạng.",
            "Log hiển thị bí mật và khóa phiên cho mục đích học tập; không dùng cho dữ liệu thật.",
        ],
    }
