"""TLS 1.2 step sequence of The Illustrated TLS 1.2 Connection, computed live."""

from __future__ import annotations

import hmac
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import padding

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
    prf,
    record,
    shared_secret,
    tls12_key_block,
    tls12_master_secret,
    tls12_open,
    tls12_seal,
    vec,
)

# (AES-128-GCM suite, AES-256-GCM suite) for each key exchange / authentication.
SUITES = {
    ("RSA key transport", "RSA"): (
        (0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
        (0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    ),
    ("DHE", "RSA"): (
        (0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    ),
    ("ECDHE", "RSA"): (
        (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    ),
    ("ECDHE", "ECDSA P-256"): (
        (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    ),
}
SCHEMES = {
    "RSA": (0x0401, "rsa_pkcs1_sha256"),
    "ECDSA P-256": (0x0403, "ecdsa_secp256r1_sha256"),
}


def _keys_outputs(master: bytes, keys: dict) -> dict:
    return {
        "MasterSecret (hex)": master.hex(),
        "client write key (hex)": keys["client_key"].hex(),
        "server write key (hex)": keys["server_key"].hex(),
        "client write IV, phần cố định (hex)": keys["client_iv"].hex(),
        "server write IV, phần cố định (hex)": keys["server_iv"].hex(),
    }


def _seal_inputs(key: bytes, iv: bytes, sequence: int) -> dict:
    return {
        "Khóa (hex)": key.hex(),
        "IV cố định (hex)": iv.hex(),
        "Số thứ tự record": sequence,
        "Nonce = IV cố định + nonce tường minh (hex)": (
            iv + sequence.to_bytes(8, "big")
        ).hex(),
    }


def _sealed(sealed: bytes) -> dict:
    return {
        "Record (hex)": sealed.hex(),
        "Header (hex)": sealed[:5].hex(),
        "Nonce tường minh (hex)": sealed[5:13].hex(),
        "Bản mã (hex)": sealed[13:-16].hex(),
        "Auth tag (hex)": sealed[-16:].hex(),
    }


def run(s: Session) -> dict:
    config, rec, wire, digest = s.config, s.rec, s.wire, s.digest
    exchange = config.exchange
    rsa_kx = exchange == "RSA key transport"
    family = "RSA key transport" if rsa_kx else exchange.split()[0]
    suite, suite_name = SUITES[(family, config.authentication)][s.key_len == 32]
    scheme, scheme_name = SCHEMES[config.authentication]

    def digest_of(data: bytes) -> bytes:
        return digest(data).digest()

    # Client Hello
    client_random = os.urandom(32)
    offered = [suite] + [
        code for pair in SUITES.values() for code, _ in pair if code != suite
    ]
    extensions = (
        extension(0, vec(b"\x00" + vec(HOSTNAME.encode(), 2), 2))
        + extension(10, vec(b"\x00\x1d\x00\x17", 2))
        + extension(11, vec(b"\x00", 1))
        + extension(13, vec(bytes.fromhex("040308040401"), 2))
        + extension(0xFF01, b"\x00")
    )
    client_hello = handshake(
        1,
        LEGACY_VERSION
        + client_random
        + b"\x00"
        + vec(b"".join(c.to_bytes(2, "big") for c in offered), 2)
        + b"\x01\x00"
        + vec(extensions, 2),
    )
    sent = record(HANDSHAKE, client_hello, b"\x03\x01")
    seen_by_b = parse_hello(wire.send("A", sent)[5:], client=True)
    if suite not in seen_by_b["suites"]:
        raise ValueError("Client Hello không chứa cipher suite yêu cầu")
    rec.add(
        "client_hello",
        "A → B",
        {"Tên server (SNI)": HOSTNAME, "Cấu hình": f"{config.cipher} / {config.hash_name}"},
        {
            "Record (hex)": sent.hex(),
            "Client random (hex)": client_random.hex(),
            "Số cipher suite đề nghị": len(offered),
            "Cipher suite đầu danh sách": f"{suite_name} ({suite:04x})",
            "Nhóm hỗ trợ": "x25519 (001d), secp256r1 (0017)",
            "Độ dài record (byte)": len(sent),
        },
    )

    # Server Hello
    server_random = os.urandom(32)
    session_id = os.urandom(32)
    server_hello = handshake(
        2,
        LEGACY_VERSION
        + server_random
        + vec(session_id, 1)
        + suite.to_bytes(2, "big")
        + b"\x00"
        + vec(extension(0xFF01, b"\x00"), 2),
    )
    sent = record(HANDSHAKE, server_hello)
    seen_by_a = parse_hello(wire.send("B", sent)[5:], client=False)
    if seen_by_a["suites"] != [suite]:
        raise ValueError("Server Hello chọn cipher suite khác yêu cầu")
    rec.add(
        "server_hello",
        "B → A",
        {"Client random nhận được (hex)": seen_by_b["random"].hex()},
        {
            "Record (hex)": sent.hex(),
            "Server random (hex)": server_random.hex(),
            "Session ID (hex)": session_id.hex(),
            "Cipher suite được chọn": f"{suite_name} ({suite:04x})",
            "Độ dài record (byte)": len(sent),
        },
    )
    transcript = client_hello + server_hello

    # Server Certificate
    certificate = handshake(11, vec(vec(s.cert_der, 3), 3))
    sent = record(HANDSHAKE, certificate)
    received = wire.send("B", sent)[5:]
    cert = check_certificate(received[10:], s.ca_cert)
    transcript += certificate
    rec.add(
        "server_cert",
        "B → A",
        {"Chứng chỉ của B": "Từ bước chuẩn bị"},
        {
            "Record (hex)": sent.hex(),
            "Chủ thể": cert.subject.rfc4514_string(),
            "CA phát hành": cert.issuer.rfc4514_string(),
            "A kiểm tra chứng chỉ": f"hợp lệ: chữ ký CA, tên {HOSTNAME}, thời hạn",
            "Độ dài record (byte)": len(sent),
        },
    )

    if not rsa_kx:
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

        # Server Key Exchange
        if family == "ECDHE":
            params = b"\x03" + GROUP_IDS[exchange].to_bytes(2, "big") + vec(b_public, 1)
            param_view = {
                "Kiểu đường cong": "named_curve (03)",
                "Đường cong": f"{exchange} ({GROUP_IDS[exchange]:04x})",
            }
        else:
            numbers = b_key.private_numbers().public_numbers.parameter_numbers
            p = numbers.p.to_bytes(len(b_public), "big")
            params = vec(p, 2) + vec(bytes([numbers.g]), 2) + vec(b_public, 2)
            param_view = {"Số nguyên tố p (hex)": p.hex(), "Phần tử sinh g": numbers.g}
        signed = client_random + server_random + params
        signature = sign(s.server_key, signed, pss=False)
        server_kx = handshake(
            12, params + scheme.to_bytes(2, "big") + vec(signature, 2)
        )
        sent = record(HANDSHAKE, server_kx)
        received = wire.send("B", sent)[5 + 4 :]
        verify(cert.public_key(), received[len(params) + 4 :], signed, pss=False)
        b_public_at_a = received[len(params) - len(b_public) : len(params)]
        transcript += server_kx
        rec.add(
            "server_kx",
            "B → A",
            {
                "Dữ liệu được ký = client random + server random + tham số (hex)": signed.hex(),
                "Khóa ký": "Khóa riêng chứng chỉ của B (xem bước chuẩn bị)",
            },
            {
                "Record (hex)": sent.hex(),
                **param_view,
                "Khóa công khai tạm thời của B (hex)": b_public.hex(),
                "Thuật toán chữ ký": f"{scheme_name} ({scheme:04x})",
                "Chữ ký (hex)": signature.hex(),
                "A xác minh chữ ký bằng khóa công khai trong chứng chỉ": "hợp lệ",
            },
        )

    # Server Hello Done
    done = handshake(14, b"")
    sent = record(HANDSHAKE, done)
    wire.send("B", sent)
    transcript += done
    rec.add("server_hello_done", "B → A", {"Nội dung": "rỗng"}, {"Record (hex)": sent.hex()})

    # Client Key Exchange Generation and Client Key Exchange
    if rsa_kx:
        premaster = LEGACY_VERSION + os.urandom(46)
        encrypted = cert.public_key().encrypt(premaster, padding.PKCS1v15())
        rec.add(
            "client_keygen_rsa",
            "A",
            {"Khóa công khai RSA trong chứng chỉ của B": "Từ bước Server Certificate"},
            {
                "PreMasterSecret (hex)": premaster.hex(),
                "PreMasterSecret mã hóa RSA PKCS#1 v1.5 (hex)": encrypted.hex(),
            },
        )
        client_kx = handshake(16, vec(encrypted, 2))
    else:
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
        client_kx = handshake(16, vec(a_public, 1 if family == "ECDHE" else 2))
    sent = record(HANDSHAKE, client_kx)
    received = wire.send("A", sent)[5 + 4 :]
    transcript += client_kx
    rec.add(
        "client_kx_rsa" if rsa_kx else "client_kx",
        "A → B",
        {"Giá trị gửi": "PreMasterSecret đã mã hóa" if rsa_kx else "Khóa công khai tạm thời của A"},
        {"Record (hex)": sent.hex(), "Độ dài record (byte)": len(sent)},
    )

    # Client Encryption Keys Calculation
    if rsa_kx:
        premaster_b = s.server_key.decrypt(received[2:], padding.PKCS1v15())
        secret_inputs = {"PreMasterSecret (hex)": premaster.hex()}
    else:
        premaster = shared_secret(exchange, a_key, b_public_at_a, strip=True)
        premaster_b = shared_secret(
            exchange, b_key, received[1:] if family == "ECDHE" else received[2:], strip=True
        )
        secret_inputs = {
            "Khóa công khai của B, từ Server Key Exchange (hex)": b_public_at_a.hex(),
            "Khóa riêng tạm thời của A (hex)": a_private,
            "PreMasterSecret = bí mật chung (hex)": premaster.hex(),
        }
    randoms = {
        "Client random (hex)": client_random.hex(),
        "Server random (hex)": server_random.hex(),
    }
    master_a = tls12_master_secret(premaster, client_random, server_random, digest)
    keys_a = tls12_key_block(master_a, client_random, server_random, digest, s.key_len)
    rec.add("client_keys", "A", {**secret_inputs, **randoms}, _keys_outputs(master_a, keys_a))

    # Client Change Cipher Spec
    sent = record(CHANGE_CIPHER_SPEC, b"\x01")
    wire.send("A", sent)
    rec.add("client_ccs", "A → B", {"Nội dung": "01"}, {"Record (hex)": sent.hex()})

    # Client Handshake Finished
    client_hash = digest_of(transcript)
    verify_data = prf(master_a, "client finished", client_hash, 12, digest)
    client_finished = handshake(20, verify_data)
    sealed = tls12_seal(keys_a["client_key"], keys_a["client_iv"], 0, HANDSHAKE, client_finished)
    received_finished = wire.send("A", sealed)
    rec.add(
        "client_finished",
        "A → B",
        {
            "Hash các thông điệp handshake (hex)": client_hash.hex(),
            **_seal_inputs(keys_a["client_key"], keys_a["client_iv"], 0),
        },
        {
            **_sealed(sealed),
            "Finished trước khi mã hóa (hex)": client_finished.hex(),
            "verify_data (hex)": verify_data.hex(),
        },
    )

    # Server Encryption Keys Calculation
    master_b = tls12_master_secret(premaster_b, client_random, server_random, digest)
    keys_b = tls12_key_block(master_b, client_random, server_random, digest, s.key_len)
    if master_b != master_a or keys_b != keys_a:
        raise ValueError("Khóa của A và B không khớp")
    opened = tls12_open(keys_b["client_key"], keys_b["client_iv"], 0, received_finished)
    expected = prf(master_b, "client finished", digest_of(transcript), 12, digest)
    if not hmac.compare_digest(opened[4:], expected):
        raise ValueError("verify_data của client không khớp")
    transcript += opened
    rec.add(
        "server_keys_rsa" if rsa_kx else "server_keys",
        "B",
        {
            ("PreMasterSecret giải mã bằng khóa riêng RSA của B (hex)" if rsa_kx
             else "PreMasterSecret = bí mật chung phía B (hex)"): premaster_b.hex(),
            **randoms,
        },
        {
            **_keys_outputs(master_b, keys_b),
            "Khớp với kết quả của A": True,
            "Finished của A sau giải mã (hex)": opened.hex(),
            "B tự tính verify_data và so sánh": "khớp",
        },
    )

    # Server Change Cipher Spec
    sent = record(CHANGE_CIPHER_SPEC, b"\x01")
    wire.send("B", sent)
    rec.add("server_ccs", "B → A", {"Nội dung": "01"}, {"Record (hex)": sent.hex()})

    # Server Handshake Finished
    server_hash = digest_of(transcript)
    verify_data = prf(master_b, "server finished", server_hash, 12, digest)
    server_finished = handshake(20, verify_data)
    sealed = tls12_seal(keys_b["server_key"], keys_b["server_iv"], 0, HANDSHAKE, server_finished)
    opened = tls12_open(keys_a["server_key"], keys_a["server_iv"], 0, wire.send("B", sealed))
    expected = prf(master_a, "server finished", server_hash, 12, digest)
    if not hmac.compare_digest(opened[4:], expected):
        raise ValueError("verify_data của server không khớp")
    rec.add(
        "server_finished",
        "B → A",
        {
            "Hash các thông điệp handshake, gồm Finished của A (hex)": server_hash.hex(),
            **_seal_inputs(keys_b["server_key"], keys_b["server_iv"], 0),
        },
        {
            **_sealed(sealed),
            "verify_data (hex)": verify_data.hex(),
            "A tự tính verify_data và so sánh": "khớp",
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
        tls12_seal(keys_a["client_key"], keys_a["client_iv"], 1 + i, APPLICATION_DATA, chunk)
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
            **_seal_inputs(keys_a["client_key"], keys_a["client_iv"], 1),
        },
        {
            **_sealed(sealed),
            "Số record": len(records),
            "Độ dài trên đường truyền (byte)": len(sealed),
            "Bị sửa khi truyền": s.tamper,
        },
    )

    # B opens the application data
    started = time.perf_counter_ns()
    try:
        opened = b"".join(
            tls12_open(keys_b["client_key"], keys_b["client_iv"], 1 + i, data)
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
            **_seal_inputs(keys_b["client_key"], keys_b["client_iv"], 1),
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
