"""Step-by-step TLS 1.2/1.3 model following the Illustrated TLS walkthroughs."""

from __future__ import annotations

import hashlib
import socket
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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


HOSTNAME = "B.local"


def _read_exact(sock, length):
    chunks = []
    while length:
        part = sock.recv(length)
        if not part:
            raise ConnectionError("Kết nối đóng trước khi nhận đủ dữ liệu")
        chunks.append(part)
        length -= len(part)
    return b"".join(chunks)


class Loopback:
    """TCP loopback connection carrying every record between A and B."""

    def __enter__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.settimeout(5)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.a = socket.create_connection(self.listener.getsockname(), timeout=5)
        self.b = self.listener.accept()[0]
        self.b.settimeout(5)
        self.total_bytes = 0
        return self

    def __exit__(self, *exc):
        for sock in (self.a, self.b, self.listener):
            sock.close()

    def send(self, sender: str, data: bytes) -> bytes:
        """Send from "A" or "B"; return the bytes the other side received."""
        source, target = (self.a, self.b) if sender == "A" else (self.b, self.a)
        source.sendall(data)
        self.total_bytes += len(data)
        return _read_exact(target, len(data))


class Recorder:
    """Collect the steps shown in the interface, timing each one."""

    def __init__(self, texts: dict, values: dict):
        self.texts, self.values = texts, values
        self.start = self.mark = time.perf_counter_ns()
        self.steps = []

    def add(self, key: str, actor: str, inputs: dict, outputs: dict):
        title, description, formula = self.texts[key]
        now = time.perf_counter_ns()
        step = {
            "index": len(self.steps) + 1,
            "key": key,
            "actor": actor,
            "title": title,
            "duration_ms": (now - self.mark) / 1_000_000,
            "offset_ms": (now - self.start) / 1_000_000,
            "description": description.format(**self.values),
            "inputs": inputs,
            "outputs": outputs,
        }
        if formula:
            step["formula"] = formula.format(**self.values)
        self.steps.append(step)
        self.mark = time.perf_counter_ns()


@dataclass
class Session:
    config: DemoConfig
    plaintext: bytes
    tamper: bool
    rec: Recorder
    wire: Loopback
    server_key: object
    cert_der: bytes
    ca_cert: x509.Certificate
    digest: object
    key_len: int


def _padding(pss: bool):
    if pss:
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    return padding.PKCS1v15()


def sign(key, data: bytes, pss: bool) -> bytes:
    """Sign with the certificate key: RSA (PSS or PKCS#1 v1.5) or ECDSA, SHA-256."""
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, _padding(pss), hashes.SHA256())
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(public_key, signature: bytes, data: bytes, pss: bool) -> None:
    """Raise InvalidSignature unless `signature` covers `data`."""
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, _padding(pss), hashes.SHA256())
    else:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))


def check_certificate(cert_der: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    """Checks A makes on the certificate received from B: CA signature, name, validity."""
    cert = x509.load_der_x509_certificate(cert_der)
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    names = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    if cert.issuer != ca_cert.subject or HOSTNAME not in names:
        raise ValueError("Tên hoặc CA của chứng chỉ không hợp lệ")
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Chứng chỉ ngoài thời hạn")
    return cert


def _make_certificates(config: DemoConfig, hash_alg):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=config.rsa_bits)
    server_key = (
        rsa.generate_private_key(public_exponent=65537, key_size=config.rsa_bits)
        if config.authentication == "RSA"
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA Minh hoa TLS")])

    def builder(subject, key):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
        )

    ca_cert = (
        builder(ca_name, ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hash_alg)
    )
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    cert = (
        builder(server_name, server_key)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), False)
        .sign(ca_key, hash_alg)
    )
    return ca_key, ca_cert, server_key, cert


def run_message(message: str, config: DemoConfig, tamper: bool = False) -> dict:
    config.validate()
    if config.version not in ("TLS 1.2", "TLS 1.3"):
        raise ValueError("Mô hình từng bước chỉ hỗ trợ TLS 1.2/1.3.")
    plaintext = message.encode("utf-8")
    if not plaintext or len(plaintext) > 32768:
        raise ValueError("Nhập thông điệp từ 1 đến 32768 byte UTF-8.")
    from . import illustrated_text, model_tls12, model_tls13

    model, texts = (
        (model_tls13, illustrated_text.TLS13)
        if config.version == "TLS 1.3"
        else (model_tls12, illustrated_text.TLS12)
    )
    sha384 = config.hash_name == "SHA-384"
    digest = hashlib.sha384 if sha384 else hashlib.sha256
    key_len = 16 if config.cipher == "AES-128-GCM" else 32
    cpu_start = time.process_time_ns()
    rec = Recorder(
        texts,
        {
            "H": "SHA384" if sha384 else "SHA256",
            "hl": digest().digest_size,
            "kl": key_len,
            "host": HOSTNAME,
        },
    )

    ca_key, ca_cert, server_key, cert = _make_certificates(
        config, hashes.SHA384() if sha384 else hashes.SHA256()
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    def pem(certificate):
        return certificate.public_bytes(serialization.Encoding.PEM).decode()

    def private_pem(key):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    rec.add(
        "prepare",
        "B / CA",
        {
            "Phiên bản": config.version,
            "Trao đổi khóa": config.exchange,
            "Xác thực server": config.authentication,
            "Mã hóa": f"{config.cipher} / {config.hash_name}",
            "Khóa RSA của CA (bit)": config.rsa_bits,
        },
        {
            "Chứng chỉ server (PEM)": pem(cert),
            "Khóa riêng chứng chỉ server (PEM)": private_pem(server_key),
            "Chứng chỉ CA tin cậy (PEM)": pem(ca_cert),
            "Khóa riêng CA thử nghiệm (PEM)": private_pem(ca_key),
            "Độ dài chứng chỉ (byte)": len(cert_der),
        },
    )

    with Loopback() as wire:
        outcome = model.run(
            Session(
                config,
                plaintext,
                tamper,
                rec,
                wire,
                server_key,
                cert_der,
                ca_cert,
                digest,
                key_len,
            )
        )
    steps = rec.steps
    elapsed = (time.perf_counter_ns() - rec.start) / 1_000_000
    setup = steps[: outcome["handshake_steps"]]
    return {
        "schema_version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": f"Mô hình {config.version} theo The Illustrated TLS Connection",
        "negotiated": " / ".join(
            (config.version, outcome["suite"], config.exchange, config.authentication)
        ),
        "config": asdict(config),
        "status": outcome["status"],
        "tampered": tamper,
        "input": message,
        "output": outcome["output"],
        "steps": steps,
        "metrics": {
            "total_ms": elapsed,
            "process_cpu_ms": (time.process_time_ns() - cpu_start) / 1_000_000,
            "setup_ms": sum(s["duration_ms"] for s in setup),
            "handshake_ms": sum(s["duration_ms"] for s in setup[1:]),
            "handshake_bytes": outcome["handshake_bytes"],
            "encrypt_ms": outcome["encrypt_ms"],
            "tcp_loopback_ms": outcome["transfer_ms"],
            "decrypt_verify_ms": outcome["decrypt_ms"],
            "plaintext_bytes": len(plaintext),
            "frame_bytes": outcome["record_bytes"],
            "wire_overhead_bytes": outcome["record_bytes"] - len(plaintext),
            "tag_bytes": 16,
            "certificate_bytes": len(cert_der),
        },
        "limitations": [
            "A và B chạy trong cùng một tiến trình; mọi record đi qua TCP loopback.",
            "Thông điệp có định dạng TLS nhưng mô hình chỉ hỗ trợ một tập cấu hình và không xử lý alert, resumption hay phân mảnh handshake; không dùng thay cho thư viện TLS.",
            "Bỏ các bước New Session Ticket, phản hồi của server và close_notify có trong tài liệu gốc.",
            "TLS 1.2 không dùng extended master secret, giống tài liệu gốc.",
            "Log hiển thị khóa riêng, bí mật và khóa phiên cho mục đích học tập; không dùng cho dữ liệu thật.",
            "Thời gian đo một lần ở mức ứng dụng; không phải benchmark.",
        ],
    }
