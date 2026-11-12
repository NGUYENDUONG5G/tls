"""TLS 1.3 step sequence of The Illustrated TLS 1.3 Connection, computed live."""

from __future__ import annotations

import hmac
import os
import time

from cryptography.exceptions import InvalidTag

from .message_demo import HOSTNAME, Session, check_certificate, sign, verify
from .tls_wire import (
    APPLICATION_DATA,
    CHANGE_CIPHER_SPEC,
    GROUP_IDS,
    HANDSHAKE,
    LEGACY_VERSION,
    MAX_FRAGMENT,
    extension,
    generate_share,
    handshake,
    parse_hello,
    record,
    shared_secret,
    tls13_application_secrets,
    tls13_handshake_secrets,
    tls13_nonce,
    tls13_open,
    tls13_seal,
    tls13_verify_data,
    vec,
)

SUITES = {
    16: (0x1301, "TLS_AES_128_GCM_SHA256"),
    32: (0x1302, "TLS_AES_256_GCM_SHA384"),
}
SCHEMES = {
    "RSA": (0x0804, "rsa_pss_rsae_sha256"),
    "ECDSA P-256": (0x0403, "ecdsa_secp256r1_sha256"),
}
SIGNATURE_CONTEXT = b" " * 64 + b"TLS 1.3, server CertificateVerify\x00"


def _key_outputs(keys: dict, first: str) -> dict:
    """Hex view of derived secrets; `first` is "handshake" or "master"."""
    stage = "handshake" if first == "handshake" else "application"
    return {
        f"{first}_secret (hex)": keys[f"{first}_secret"].hex(),
        f"server {stage} traffic secret (hex)": keys["server_secret"].hex(),
        f"client {stage} traffic secret (hex)": keys["client_secret"].hex(),
        f"server {stage} key (hex)": keys["server_key"].hex(),
        f"server {stage} IV (hex)": keys["server_iv"].hex(),
        f"client {stage} key (hex)": keys["client_key"].hex(),
        f"client {stage} IV (hex)": keys["client_iv"].hex(),
    }


def _seal_inputs(key: bytes, iv: bytes, sequence: int) -> dict:
    return {
        "Khóa (hex)": key.hex(),
        "IV (hex)": iv.hex(),
        "Số thứ tự record": sequence,
        "Nonce = IV XOR số thứ tự (hex)": tls13_nonce(iv, sequence).hex(),
    }


def _wrapped(sealed: bytes) -> dict:
    return {
        "Record đã bọc (hex)": sealed.hex(),
        "Header, cũng là dữ liệu xác thực bổ sung (hex)": sealed[:5].hex(),
        "Bản mã (hex)": sealed[5:-16].hex(),
        "Auth tag (hex)": sealed[-16:].hex(),
    }


def run(s: Session) -> dict:
    config, rec, wire, digest = s.config, s.rec, s.wire, s.digest
    exchange = config.exchange
    group = GROUP_IDS[exchange].to_bytes(2, "big")
    suite, suite_name = SUITES[s.key_len]
    other_suite = SUITES[48 - s.key_len][0]
    scheme, scheme_name = SCHEMES[config.authentication]

    def digest_of(data: bytes) -> bytes:
        return digest(data).digest()

    # Client Key Exchange Generation
    a_key, a_private, a_public = generate_share(exchange)
    rec.add(
        "client_keygen",
        "A",
        {"Nhóm trao đổi khóa": exchange},
        {
            "Khóa riêng tạm thời của A (hex)": a_private,
            "Khóa công khai tạm thời của A (hex)": a_public.hex(),
        },
    )

    # Client Hello
    client_random, session_id = os.urandom(32), os.urandom(32)
    extensions = (
        extension(0, vec(b"\x00" + vec(HOSTNAME.encode(), 2), 2))
        + extension(
            10, vec(b"".join(g.to_bytes(2, "big") for g in GROUP_IDS.values()), 2)
        )
        + extension(13, vec(bytes.fromhex("040308040401"), 2))
        + extension(43, vec(b"\x03\x04", 1))
        + extension(51, vec(group + vec(a_public, 2), 2))
    )
    client_hello = handshake(
        1,
        LEGACY_VERSION
        + client_random
        + vec(session_id, 1)
        + vec(suite.to_bytes(2, "big") + other_suite.to_bytes(2, "big"), 2)
        + b"\x01\x00"
        + vec(extensions, 2),
    )
    sent = record(HANDSHAKE, client_hello, b"\x03\x01")
    seen_by_b = parse_hello(wire.send("A", sent)[5:], client=True)
    a_public_at_b = seen_by_b["extensions"][51][6:]
    rec.add(
        "client_hello",
        "A → B",
        {
            "Khóa công khai tạm thời của A (hex)": a_public.hex(),
            "Tên server (SNI)": HOSTNAME,
        },
        {
            "Record (hex)": sent.hex(),
            "Client random (hex)": client_random.hex(),
            "Session ID giả (hex)": session_id.hex(),
            "Cipher suite đề nghị": f"{suite_name} ({suite:04x}), {SUITES[48 - s.key_len][1]} ({other_suite:04x})",
            "Phiên bản hỗ trợ": "TLS 1.3 (03 04)",
            "Key share": f"{exchange} ({group.hex()})",
            "Thuật toán chữ ký chấp nhận": "ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256",
            "Độ dài record (byte)": len(sent),
        },
    )

    # Server Key Exchange Generation
    b_key, b_private, b_public = generate_share(exchange)
    rec.add(
        "server_keygen",
        "B",
        {"Nhóm trao đổi khóa": exchange},
        {
            "Khóa riêng tạm thời của B (hex)": b_private,
            "Khóa công khai tạm thời của B (hex)": b_public.hex(),
        },
    )

    # Server Hello
    server_random = os.urandom(32)
    server_hello = handshake(
        2,
        LEGACY_VERSION
        + server_random
        + vec(seen_by_b["session_id"], 1)
        + suite.to_bytes(2, "big")
        + b"\x00"
        + vec(
            extension(43, b"\x03\x04") + extension(51, group + vec(b_public, 2)),
            2,
        ),
    )
    sent = record(HANDSHAKE, server_hello)
    seen_by_a = parse_hello(wire.send("B", sent)[5:], client=False)
    b_public_at_a = seen_by_a["extensions"][51][4:]
    if seen_by_a["suites"] != [suite] or seen_by_a["session_id"] != session_id:
        raise ValueError("Server Hello không khớp với Client Hello")
    rec.add(
        "server_hello",
        "B → A",
        {
            "Khóa công khai tạm thời của B (hex)": b_public.hex(),
            "Session ID nhận từ A (hex)": seen_by_b["session_id"].hex(),
        },
        {
            "Record (hex)": sent.hex(),
            "Server random (hex)": server_random.hex(),
            "Cipher suite được chọn": f"{suite_name} ({suite:04x})",
            "Phiên bản được chọn": "TLS 1.3 (03 04)",
            "Key share": f"{exchange} ({group.hex()})",
            "Độ dài record (byte)": len(sent),
        },
    )
    transcript = client_hello + server_hello

    # Server / Client Handshake Keys Calc
    hello_hash = digest_of(transcript)
    shared_b = shared_secret(exchange, b_key, a_public_at_b)
    keys_b = tls13_handshake_secrets(shared_b, hello_hash, digest, s.key_len)
    rec.add(
        "server_hs_keys",
        "B",
        {
            "Khóa công khai của A, từ Client Hello (hex)": a_public_at_b.hex(),
            "Khóa riêng tạm thời của B (hex)": b_private,
            "hello_hash (hex)": hello_hash.hex(),
        },
        {"shared_secret (hex)": shared_b.hex(), **_key_outputs(keys_b, "handshake")},
    )
    shared_a = shared_secret(exchange, a_key, b_public_at_a)
    keys_a = tls13_handshake_secrets(shared_a, hello_hash, digest, s.key_len)
    if keys_a != keys_b:
        raise ValueError("Khóa handshake của A và B không khớp")
    rec.add(
        "client_hs_keys",
        "A",
        {
            "Khóa công khai của B, từ Server Hello (hex)": b_public_at_a.hex(),
            "Khóa riêng tạm thời của A (hex)": a_private,
            "hello_hash (hex)": hello_hash.hex(),
        },
        {
            "shared_secret (hex)": shared_a.hex(),
            "Khớp với kết quả của B": True,
            **_key_outputs(keys_a, "handshake"),
        },
    )

    # Server Change Cipher Spec
    sent = record(CHANGE_CIPHER_SPEC, b"\x01")
    wire.send("B", sent)
    rec.add("server_ccs", "B → A", {"Nội dung": "01"}, {"Record (hex)": sent.hex()})

    def from_server(sequence: int, message: bytes):
        """B wraps a handshake message; A unwraps it with its own keys."""
        sealed = tls13_seal(
            keys_b["server_key"], keys_b["server_iv"], sequence, HANDSHAKE, message
        )
        kind, opened = tls13_open(
            keys_a["server_key"], keys_a["server_iv"], sequence, wire.send("B", sealed)
        )
        if kind != HANDSHAKE:
            raise ValueError("Kiểu record bên trong không phải handshake")
        return sealed, opened

    def server_inputs(sequence: int) -> dict:
        return _seal_inputs(keys_b["server_key"], keys_b["server_iv"], sequence)

    # Server Encrypted Extensions
    message = handshake(8, vec(b"", 2))
    sealed, opened = from_server(0, message)
    transcript += opened
    rec.add(
        "server_ee",
        "B → A",
        server_inputs(0),
        {
            **_wrapped(sealed),
            "Encrypted Extensions sau giải mã (hex)": opened.hex(),
            "Kiểu record thật (byte cuối sau giải mã)": "16 (handshake)",
        },
    )

    # Server Certificate
    message = handshake(11, b"\x00" + vec(vec(s.cert_der, 3) + vec(b"", 2), 3))
    sealed, opened = from_server(1, message)
    transcript += opened
    size = int.from_bytes(opened[8:11], "big")
    cert = check_certificate(opened[11 : 11 + size], s.ca_cert)
    rec.add(
        "server_cert",
        "B → A",
        server_inputs(1),
        {
            **_wrapped(sealed),
            "Certificate sau giải mã (hex)": opened.hex(),
            "Chủ thể": cert.subject.rfc4514_string(),
            "CA phát hành": cert.issuer.rfc4514_string(),
            "A kiểm tra chứng chỉ": f"hợp lệ: chữ ký CA, tên {HOSTNAME}, thời hạn",
        },
    )

    # Server Certificate Verify
    signed_hash = digest_of(transcript)
    signature = sign(s.server_key, SIGNATURE_CONTEXT + signed_hash, pss=True)
    message = handshake(15, scheme.to_bytes(2, "big") + vec(signature, 2))
    sealed, opened = from_server(2, message)
    verify(cert.public_key(), opened[8:], SIGNATURE_CONTEXT + digest_of(transcript), True)
    transcript += opened
    rec.add(
        "server_cert_verify",
        "B → A",
        {
            "Hash các thông điệp handshake đến Certificate (hex)": signed_hash.hex(),
            "Khóa ký": "Khóa riêng chứng chỉ của B (xem bước chuẩn bị)",
            **server_inputs(2),
        },
        {
            **_wrapped(sealed),
            "Thuật toán chữ ký": f"{scheme_name} ({scheme:04x})",
            "Chữ ký (hex)": signature.hex(),
            "A xác minh chữ ký bằng khóa công khai trong chứng chỉ": "hợp lệ",
        },
    )

    # Server Handshake Finished
    finished_hash = digest_of(transcript)
    verify_data = tls13_verify_data(keys_b["server_secret"], finished_hash, digest)
    sealed, opened = from_server(3, handshake(20, verify_data))
    expected = tls13_verify_data(keys_a["server_secret"], digest_of(transcript), digest)
    if not hmac.compare_digest(opened[4:], expected):
        raise ValueError("verify_data của server không khớp")
    transcript += opened
    rec.add(
        "server_finished",
        "B → A",
        {
            "server handshake traffic secret (hex)": keys_b["server_secret"].hex(),
            "finished_hash (hex)": finished_hash.hex(),
            **server_inputs(3),
        },
        {
            **_wrapped(sealed),
            "verify_data (hex)": verify_data.hex(),
            "A tự tính verify_data và so sánh": "khớp",
        },
    )

    # Server / Client Application Keys Calc
    handshake_hash = digest_of(transcript)
    app_b = tls13_application_secrets(
        keys_b["handshake_secret"], handshake_hash, digest, s.key_len
    )
    key_inputs = {
        "handshake_secret (hex)": keys_b["handshake_secret"].hex(),
        "handshake_hash, Client Hello đến Server Finished (hex)": handshake_hash.hex(),
    }
    rec.add("server_app_keys", "B", key_inputs, _key_outputs(app_b, "master"))
    app_a = tls13_application_secrets(
        keys_a["handshake_secret"], handshake_hash, digest, s.key_len
    )
    if app_a != app_b:
        raise ValueError("Khóa ứng dụng của A và B không khớp")
    rec.add(
        "client_app_keys",
        "A",
        key_inputs,
        {"Khớp với kết quả của B": True, **_key_outputs(app_a, "master")},
    )

    # Client Change Cipher Spec
    sent = record(CHANGE_CIPHER_SPEC, b"\x01")
    wire.send("A", sent)
    rec.add("client_ccs", "A → B", {"Nội dung": "01"}, {"Record (hex)": sent.hex()})

    # Client Handshake Finished
    verify_data = tls13_verify_data(keys_a["client_secret"], handshake_hash, digest)
    sealed = tls13_seal(
        keys_a["client_key"], keys_a["client_iv"], 0, HANDSHAKE, handshake(20, verify_data)
    )
    _, opened = tls13_open(
        keys_b["client_key"], keys_b["client_iv"], 0, wire.send("A", sealed)
    )
    expected = tls13_verify_data(keys_b["client_secret"], handshake_hash, digest)
    if not hmac.compare_digest(opened[4:], expected):
        raise ValueError("verify_data của client không khớp")
    rec.add(
        "client_finished",
        "A → B",
        {
            "client handshake traffic secret (hex)": keys_a["client_secret"].hex(),
            "finished_hash (hex)": handshake_hash.hex(),
            **_seal_inputs(keys_a["client_key"], keys_a["client_iv"], 0),
        },
        {
            **_wrapped(sealed),
            "verify_data (hex)": verify_data.hex(),
            "B tự tính verify_data và so sánh": "khớp",
        },
    )
    handshake_steps, handshake_bytes = len(rec.steps), wire.total_bytes

    # Client Application Data
    chunks = [
        s.plaintext[i : i + MAX_FRAGMENT]
        for i in range(0, len(s.plaintext), MAX_FRAGMENT)
    ]
    started = time.perf_counter_ns()
    records = [
        tls13_seal(
            app_a["client_key"], app_a["client_iv"], i, APPLICATION_DATA, chunk
        )
        for i, chunk in enumerate(chunks)
    ]
    encrypt_ms = (time.perf_counter_ns() - started) / 1_000_000
    on_wire = list(records)
    if s.tamper:
        on_wire[-1] = on_wire[-1][:-1] + bytes([on_wire[-1][-1] ^ 1])
    started = time.perf_counter_ns()
    received = [wire.send("A", data) for data in on_wire]
    transfer_ms = (time.perf_counter_ns() - started) / 1_000_000
    sealed = b"".join(records)
    rec.add(
        "client_app_data",
        "A → B",
        {
            "Thông điệp (UTF-8)": s.plaintext.decode("utf-8"),
            "Bản rõ (hex)": s.plaintext.hex(),
            **_seal_inputs(app_a["client_key"], app_a["client_iv"], 0),
        },
        {
            **_wrapped(sealed),
            "Số record": len(records),
            "Độ dài trên đường truyền (byte)": len(sealed),
            "Bị sửa khi truyền": s.tamper,
        },
    )

    # B opens the application data
    started = time.perf_counter_ns()
    try:
        opened = b"".join(
            tls13_open(app_b["client_key"], app_b["client_iv"], i, data)[1]
            for i, data in enumerate(received)
        )
        status, output = "success", opened.decode("utf-8")
        outputs = {
            "Kiểm tra auth tag": "hợp lệ",
            "Thông điệp B nhận (UTF-8)": output,
            "Bản rõ (hex)": opened.hex(),
            "Khớp thông điệp ban đầu": opened == s.plaintext,
        }
    except InvalidTag:
        status, output = "rejected", None
        outputs = {
            "Kiểm tra auth tag": "không hợp lệ",
            "Thông điệp B nhận (UTF-8)": None,
            "Kết quả": "B hủy record và báo lỗi bad_record_mac; không trả bản rõ.",
        }
    decrypt_ms = (time.perf_counter_ns() - started) / 1_000_000
    rec.add(
        "server_decrypt",
        "B",
        {
            "Record B nhận (hex)": b"".join(received).hex(),
            **_seal_inputs(app_b["client_key"], app_b["client_iv"], 0),
        },
        outputs,
    )
    return {
        "status": status,
        "output": output,
        "suite": suite_name,
        "handshake_steps": handshake_steps,
        "handshake_bytes": handshake_bytes,
        "encrypt_ms": encrypt_ms,
        "transfer_ms": transfer_ms,
        "decrypt_ms": decrypt_ms,
        "record_bytes": len(sealed),
    }
