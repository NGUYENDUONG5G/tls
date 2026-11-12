"""Real TLS with MemoryBIO, captured TLS records and loopback transport."""

from __future__ import annotations

import hashlib
import socket
import ssl
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .message_demo import DemoConfig, _read_exact


def negotiated_group(chunks, version):
    """Read the cleartext ServerKeyExchange or ServerHello from TLS records."""
    data = b"".join(chunks)
    fragments = b""
    pos = 0
    while pos + 5 <= len(data):
        kind = data[pos]
        size = int.from_bytes(data[pos + 3 : pos + 5], "big")
        if pos + 5 + size > len(data):
            break
        if kind == 20:
            break  # Subsequent records are encrypted.
        if kind == 22:
            fragments += data[pos + 5 : pos + 5 + size]
        pos += 5 + size
    pos = 0
    while pos + 4 <= len(fragments):
        kind = fragments[pos]
        size = int.from_bytes(fragments[pos + 1 : pos + 4], "big")
        body = fragments[pos + 4 : pos + 4 + size]
        if len(body) != size:
            break
        if version == "TLS 1.2" and kind == 12 and len(body) >= 3:
            if body[0] == 3:
                return {23: "ECDHE P-256", 29: "ECDHE X25519"}.get(
                    int.from_bytes(body[1:3], "big")
                )
            p_len = int.from_bytes(body[:2], "big")
            if p_len and len(body) >= 2 + p_len:
                from .dh_group import P

                if int.from_bytes(body[2 : 2 + p_len], "big") == P:
                    return "DHE 2048"
        if version == "TLS 1.3" and kind == 2 and len(body) >= 38:
            cursor = 34
            session_len = body[cursor]
            cursor += 1 + session_len + 3
            if cursor + 2 > len(body):
                return None
            extensions_len = int.from_bytes(body[cursor : cursor + 2], "big")
            cursor += 2
            end = min(len(body), cursor + extensions_len)
            while cursor + 4 <= end:
                ext = int.from_bytes(body[cursor : cursor + 2], "big")
                length = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
                cursor += 4
                if cursor + length > end:
                    break
                if ext == 51 and length >= 2:
                    return {
                        23: "ECDHE P-256",
                        29: "ECDHE X25519",
                        256: "DHE ffdhe2048",
                    }.get(int.from_bytes(body[cursor : cursor + 2], "big"))
                cursor += length
        pos += 4 + size
    return None


def run_real_tls(message: str, config: DemoConfig, tamper=False) -> dict:
    config.validate()
    if config.version not in ("TLS 1.2", "TLS 1.3"):
        raise ValueError("Dùng backend container cho SSL 2.0 đến TLS 1.1.")
    plaintext = message.encode("utf-8")
    if not 1 <= len(plaintext) <= 16000:
        raise ValueError("TLS thật hỗ trợ thông điệp 1–16000 byte UTF-8.")
    start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    steps = []

    def step(actor, title, t, details, description):
        end = time.perf_counter_ns()
        steps.append(
            {
                "index": len(steps) + 1,
                "actor": actor,
                "title": title,
                "duration_ms": (end - t) / 1e6,
                "offset_ms": (end - start) / 1e6,
                "description": description,
                "details": details,
            }
        )

    t = time.perf_counter_ns()
    digest = hashes.SHA384() if config.hash_name == "SHA-384" else hashes.SHA256()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=config.rsa_bits)
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=config.rsa_bits)
        if config.authentication == "RSA"
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA TLS thuc")])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "B.local")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, digest)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("B.local")]), False)
        .sign(ca_key, digest)
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    if config.version == "TLS 1.3":
        suite = (
            "TLS_AES_128_GCM_SHA256"
            if config.cipher == "AES-128-GCM"
            else "TLS_AES_256_GCM_SHA384"
        )
    else:
        prefix = {
            "RSA key transport": "",
            "DHE 2048": "DHE-RSA-",
            "ECDHE X25519": f"ECDHE-{'ECDSA' if config.authentication.startswith('ECDSA') else 'RSA'}-",
            "ECDHE P-256": f"ECDHE-{'ECDSA' if config.authentication.startswith('ECDSA') else 'RSA'}-",
        }[config.exchange]
        suite = prefix + (
            "AES128-GCM-SHA256"
            if config.cipher == "AES-128-GCM"
            else "AES256-GCM-SHA384"
        )
    protocol = {"TLS 1.2": ssl.TLSVersion.TLSv1_2, "TLS 1.3": ssl.TLSVersion.TLSv1_3}[
        config.version
    ]
    observed_protocol = {"TLS 1.2": "TLSv1.2", "TLS 1.3": "TLSv1.3"}[config.version]
    with tempfile.TemporaryDirectory(prefix="tls-real-") as tmp:
        certfile = Path(tmp) / "server.pem"
        keyfile = Path(tmp) / "server.key"
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        keyfile.write_bytes(private_pem)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        for ctx in (server_context, client_context):
            ctx.minimum_version = ctx.maximum_version = protocol
            if config.version != "TLS 1.3":
                ctx.set_ciphers(suite)
            if config.exchange.startswith("ECDHE") and not (
                config.version == "TLS 1.2"
                and config.exchange == "ECDHE X25519"
                and config.authentication.startswith("ECDSA")
            ):
                ctx.set_ecdh_curve(
                    "X25519" if config.exchange == "ECDHE X25519" else "prime256v1"
                )
        if config.exchange == "DHE 2048":
            from .dh_group import pem

            dhfile = Path(tmp) / "dh.pem"
            dhfile.write_bytes(pem())
            server_context.load_dh_params(str(dhfile))
        server_context.load_cert_chain(str(certfile), str(keyfile))
        client_context.load_verify_locations(
            cadata=ca.public_bytes(serialization.Encoding.PEM).decode()
        )
        client_context.check_hostname = True
        step(
            "B / CA",
            "Chuẩn bị khóa và chứng chỉ",
            t,
            {
                "authentication": config.authentication,
                "certificate_key_bits": key.key_size,
                "rsa_ca_bits": config.rsa_bits,
                "certificate_bytes": len(cert_der),
                "certificate_sha256": hashlib.sha256(cert_der).hexdigest(),
                "certificate_pem": cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode(),
                "ca_certificate_pem": ca.public_bytes(
                    serialization.Encoding.PEM
                ).decode(),
                "server_public_key_pem": key.public_key()
                .public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode(),
                "server_private_key_pem": private_pem.decode(),
                "ca_private_key_pem": ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode(),
                "openssl": ssl.OPENSSL_VERSION,
                "requested_cipher": suite,
                "requested_group": config.exchange,
            },
            "CA RSA ký chứng chỉ server; khóa chứng chỉ server có thể là RSA hoặc ECDSA.",
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            with socket.create_connection(
                listener.getsockname(), timeout=5
            ) as transport_a:
                with listener.accept()[0] as transport_b:
                    transport_b.settimeout(5)
                    ain, aout, bin_, bout = (
                        ssl.MemoryBIO(),
                        ssl.MemoryBIO(),
                        ssl.MemoryBIO(),
                        ssl.MemoryBIO(),
                    )
                    a = client_context.wrap_bio(
                        ain, aout, server_side=False, server_hostname="B.local"
                    )
                    b = server_context.wrap_bio(bin_, bout, server_side=True)
                    server_chunks = []

                    def move(source, destination, write_sock, read_sock, actor, title):
                        data = source.read()
                        if not data:
                            return 0
                        t0 = time.perf_counter_ns()
                        write_sock.sendall(data)
                        received = _read_exact(read_sock, len(data))
                        destination.write(received)
                        if actor == "B → A":
                            server_chunks.append(data)
                        records = []
                        offset = 0
                        while offset + 5 <= len(data):
                            size = int.from_bytes(data[offset + 3 : offset + 5], "big")
                            records.append(
                                {
                                    "type": data[offset],
                                    "record_version": data[
                                        offset + 1 : offset + 3
                                    ].hex(),
                                    "payload_bytes": size,
                                }
                            )
                            offset += 5 + size
                        step(
                            actor,
                            title,
                            t0,
                            {
                                "bytes": len(data),
                                "records": records,
                                "wire_hex": data.hex(),
                            },
                            "Đây là các TLS record thực được gửi trên TCP loopback.",
                        )
                        return len(data)

                    t = time.perf_counter_ns()
                    a_done = b_done = False
                    handshake_bytes = 0
                    for _ in range(20):
                        if not a_done:
                            try:
                                a.do_handshake()
                                a_done = True
                            except ssl.SSLWantReadError:
                                pass
                        handshake_bytes += move(
                            aout,
                            bin_,
                            transport_a,
                            transport_b,
                            "A → B",
                            "Gửi bản ghi handshake từ A",
                        )
                        if not b_done:
                            try:
                                b.do_handshake()
                                b_done = True
                            except ssl.SSLWantReadError:
                                pass
                        handshake_bytes += move(
                            bout,
                            ain,
                            transport_b,
                            transport_a,
                            "B → A",
                            "Gửi bản ghi handshake từ B",
                        )
                        if a_done and b_done:
                            break
                    if not (a_done and b_done):
                        raise RuntimeError("Handshake TLS không hoàn tất")
                    handshake_ms = (time.perf_counter_ns() - t) / 1e6
                    observed = a.cipher()
                    if a.version() != observed_protocol or observed[0] != suite:
                        raise RuntimeError(
                            f"Thương lượng khác yêu cầu: {a.version()} {observed[0]}. Python ssl không ép được cipher TLS 1.3 trên backend này; hãy chọn suite được thương lượng hoặc dùng mô hình."
                        )
                    peer = x509.load_der_x509_certificate(
                        a.getpeercert(binary_form=True)
                    ).public_key()
                    auth = (
                        "RSA"
                        if isinstance(peer, rsa.RSAPublicKey)
                        else "ECDSA P-256"
                        if isinstance(peer, ec.EllipticCurvePublicKey)
                        and isinstance(peer.curve, ec.SECP256R1)
                        else "unknown"
                    )
                    if auth != config.authentication:
                        raise RuntimeError(
                            f"Loại khóa chứng chỉ thực tế {auth} khác yêu cầu {config.authentication}"
                        )
                    group = (
                        negotiated_group(server_chunks, config.version)
                        if config.exchange != "RSA key transport"
                        else None
                    )
                    if (
                        config.exchange != "RSA key transport"
                        and group != config.exchange
                    ):
                        raise RuntimeError(
                            f"Không xác minh được nhóm đã thương lượng: yêu cầu {config.exchange}, quan sát {group}."
                        )
                    step(
                        "A ↔ B",
                        "Handshake TLS hoàn tất",
                        t,
                        {
                            "version": a.version(),
                            "cipher": observed[0],
                            "cipher_bits": observed[2],
                            "authentication": auth,
                            "requested_group": config.exchange,
                            "observed_group": group,
                            "hostname": "B.local",
                            "certificate_verified": True,
                            "handshake_bytes": handshake_bytes,
                            "handshake_ms": handshake_ms,
                            "openssl": ssl.OPENSSL_VERSION,
                        },
                        "Kiểm tra chứng chỉ và nhóm trao đổi khóa thực tế trong handshake, cùng phiên bản và bộ mã.",
                    )
                    t = time.perf_counter_ns()
                    a.write(plaintext)
                    record = aout.read()
                    step(
                        "A",
                        "Mã hóa thành TLS application record",
                        t,
                        {
                            "plaintext_utf8": message,
                            "plaintext_bytes": len(plaintext),
                            "tls_record_hex": record.hex(),
                            "tls_record_bytes": len(record),
                            "record_type": record[0],
                        },
                        "OpenSSL mã hóa thông điệp và xuất TLS record; khóa phiên nằm trong thư viện.",
                    )
                    t = time.perf_counter_ns()
                    wire = record
                    if tamper:
                        wire = wire[:-1] + bytes([wire[-1] ^ 1])
                    transport_a.sendall(wire)
                    received = _read_exact(transport_b, len(wire))
                    bin_.write(received)
                    step(
                        "A → B",
                        "Truyền TLS record qua TCP loopback",
                        t,
                        {
                            "address": "127.0.0.1",
                            "wire_hex": wire.hex(),
                            "wire_bytes": len(wire),
                            "tampered": tamper,
                        },
                        "Truyền TLS record thực qua TCP. Không tính TCP/IP header.",
                    )
                    t = time.perf_counter_ns()
                    try:
                        decrypted = b.read(len(plaintext) + 1)
                        output = decrypted.decode("utf-8")
                        status = "success"
                        details = {
                            "plaintext_utf8": output,
                            "matches_original": decrypted == plaintext,
                            "tag": "được OpenSSL xác thực",
                        }
                    except ssl.SSLError as exc:
                        if not tamper:
                            raise
                        output = None
                        status = "rejected"
                        details = {
                            "tag": "không hợp lệ",
                            "plaintext_utf8": None,
                            "error": str(exc),
                        }
                    step(
                        "B",
                        "Xác thực và giải mã TLS record",
                        t,
                        details,
                        "B dùng OpenSSL xác thực record và chỉ trả bản rõ khi kiểm tra thành công.",
                    )
    total = (time.perf_counter_ns() - start) / 1e6
    cpu = (time.process_time_ns() - cpu_start) / 1e6
    enc = next(
        s["duration_ms"]
        for s in steps
        if s["title"] == "Mã hóa thành TLS application record"
    )
    network = next(
        s["duration_ms"]
        for s in steps
        if s["title"] == "Truyền TLS record qua TCP loopback"
    )
    dec = steps[-1]["duration_ms"]
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": f"{config.version} thực qua Python ssl/OpenSSL và TCP loopback",
        "config": asdict(config),
        "status": status,
        "tampered": tamper,
        "input": message,
        "output": output,
        "steps": steps,
        "metrics": {
            "total_ms": total,
            "process_cpu_ms": cpu,
            "setup_ms": steps[0]["duration_ms"] + handshake_ms,
            "handshake_ms": handshake_ms,
            "handshake_bytes": handshake_bytes,
            "encrypt_ms": enc,
            "tcp_loopback_ms": network,
            "tcp_frame_mib_s": len(record) / (1024**2) / (network / 1000),
            "decrypt_verify_ms": dec,
            "plaintext_bytes": len(plaintext),
            "ciphertext_bytes": len(plaintext) if config.version == "TLS 1.2" else None,
            "tag_bytes": 16 if config.version in ("TLS 1.2", "TLS 1.3") else None,
            "nonce_bytes": 8 if config.version == "TLS 1.2" else None,
            "frame_bytes": len(record),
            "wire_overhead_bytes": len(record) - len(plaintext),
            "certificate_bytes": len(cert_der),
        },
        "limitations": [
            "Log chứa khóa riêng của chứng chỉ thí nghiệm và CA; không dùng khóa này cho dữ liệu thật.",
            "TLS thực được Python ssl/OpenSSL thực hiện; API hiện dùng không xuất khóa riêng DH/ECDHE tạm thời; ứng dụng chưa trích xuất khóa phiên.",
            "Tổng thời gian gồm tạo khóa và chứng chỉ; handshake_ms đo riêng sau bước chuẩn bị.",
            "Handshake và dữ liệu qua TCP loopback; CPU là tổng tiến trình, không tách A/B.",
            "Không tính header TCP/IP. Tốc độ của một thông điệp không phải benchmark mạng.",
        ],
    }
