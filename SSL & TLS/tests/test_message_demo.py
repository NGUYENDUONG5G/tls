import hashlib
import json
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ssl_tls_lab import tls_wire
from ssl_tls_lab.message_demo import DemoConfig, run_message
from ssl_tls_lab.protocols import run_protocol

TLS12_STEPS = [
    "Chuẩn bị khóa và chứng chỉ của B",
    "Client Hello",
    "Server Hello",
    "Server Certificate",
    "Server Key Exchange Generation",
    "Server Key Exchange",
    "Server Hello Done",
    "Client Key Exchange Generation",
    "Client Key Exchange",
    "Client Encryption Keys Calculation",
    "Client Change Cipher Spec",
    "Client Handshake Finished",
    "Server Encryption Keys Calculation",
    "Server Change Cipher Spec",
    "Server Handshake Finished",
    "Client Application Data",
    "B xác thực tag và giải mã",
]
TLS13_STEPS = [
    "Chuẩn bị khóa và chứng chỉ của B",
    "Client Key Exchange Generation",
    "Client Hello",
    "Server Key Exchange Generation",
    "Server Hello",
    "Server Handshake Keys Calc",
    "Client Handshake Keys Calc",
    "Server Change Cipher Spec",
    "Server Encrypted Extensions",
    "Server Certificate",
    "Server Certificate Verify",
    "Server Handshake Finished",
    "Server Application Keys Calc",
    "Client Application Keys Calc",
    "Client Change Cipher Spec",
    "Client Handshake Finished",
    "Client Application Data",
    "B xác thực tag và giải mã",
]
MODEL_CONFIGS = [
    DemoConfig(),
    DemoConfig(cipher="AES-256-GCM", hash_name="SHA-384"),
    DemoConfig(exchange="DHE 2048"),
    DemoConfig(exchange="ECDHE X25519"),
    DemoConfig(exchange="ECDHE P-256", cipher="AES-256-GCM", hash_name="SHA-384"),
    DemoConfig(exchange="ECDHE X25519", authentication="ECDSA P-256"),
    DemoConfig(exchange="ECDHE P-256", authentication="ECDSA P-256"),
    DemoConfig(version="TLS 1.3", exchange="ECDHE X25519"),
    DemoConfig(
        version="TLS 1.3",
        exchange="ECDHE X25519",
        cipher="AES-256-GCM",
        hash_name="SHA-384",
    ),
    DemoConfig(version="TLS 1.3", exchange="ECDHE P-256", authentication="ECDSA P-256"),
    DemoConfig(version="TLS 1.3", exchange="DHE ffdhe2048"),
    DemoConfig(
        version="TLS 1.3",
        exchange="DHE ffdhe2048",
        authentication="ECDSA P-256",
        cipher="AES-256-GCM",
        hash_name="SHA-384",
    ),
]


def assert_key_matches_certificate(private_pem, certificate_pem):
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())

    def public_bytes(public):
        return public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    assert public_bytes(key.public_key()) == public_bytes(cert.public_key())


def step(result, title):
    return next(s for s in result["steps"] if s["title"] == title)


# --- Known values published in The Illustrated TLS 1.2 / 1.3 Connection ----

SHARED = bytes.fromhex(
    "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"
)


def test_tls13_handshake_keys_match_illustrated_tls13():
    hello_hash = bytes.fromhex(
        "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4"
        "f4d34555112077f16e079019d5a845bd"
    )
    keys = tls_wire.tls13_handshake_secrets(SHARED, hello_hash, hashlib.sha384, 32)
    assert keys["handshake_secret"].hex() == (
        "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c92"
        "9078d2caa0936231c38d1725f179d299"
    )
    assert keys["server_secret"].hex() == (
        "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a"
        "68f481f2b019f9403a3051908a5d1622"
    )
    assert keys["server_key"].hex() == (
        "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f"
    )
    assert keys["server_iv"].hex() == "9563bc8b590f671f488d2da3"
    assert keys["client_key"].hex() == (
        "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69"
    )
    assert keys["client_iv"].hex() == "4256d2e0e88babdd05eb2f27"


def test_tls13_application_keys_and_record_match_illustrated_tls13():
    handshake_secret = bytes.fromhex(
        "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c92"
        "9078d2caa0936231c38d1725f179d299"
    )
    handshake_hash = bytes.fromhex(
        "fa6800169a6baac19159524fa7b9721b41be3c9db6f3f93fa5ff7e3db3ece204"
        "d2b456c51046e40ec5312c55a86126f5"
    )
    keys = tls_wire.tls13_application_secrets(
        handshake_secret, handshake_hash, hashlib.sha384, 32
    )
    assert keys["server_key"].hex() == (
        "01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27"
    )
    assert keys["server_iv"].hex() == "196a750b0c5049c0cc51a541"
    assert keys["client_key"].hex() == (
        "de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc"
    )
    assert keys["client_iv"].hex() == "bb007956f474b25de902432f"
    # First wrapped record of the server: Encrypted Extensions.
    sealed = tls_wire.tls13_seal(
        bytes.fromhex(
            "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f"
        ),
        bytes.fromhex("9563bc8b590f671f488d2da3"),
        0,
        tls_wire.HANDSHAKE,
        bytes.fromhex("080000020000"),
    )
    assert sealed.hex() == (
        "17030300176be02f9da7c2dc9ddef56f2468b90adfa25101ab0344ae"
    )


def test_tls12_master_secret_matches_illustrated_tls12():
    client_random = bytes(range(0x00, 0x20))
    server_random = bytes(range(0x70, 0x90))
    master = tls_wire.tls12_master_secret(
        SHARED, client_random, server_random, hashlib.sha256
    )
    assert master.hex() == (
        "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049"
        "781c8e19fc1eb2a7387ac06ae237344c"
    )


# --- Step-by-step model ----------------------------------------------------


@pytest.mark.parametrize("config", MODEL_CONFIGS)
def test_model_follows_illustrated_steps_and_delivers_message(config):
    text = "Chào B! 🔐 こんにちは"
    result = run_protocol(text, config)
    assert result["status"] == "success" and result["output"] == text
    titles = [s["title"] for s in result["steps"]]
    if config.version == "TLS 1.3":
        assert titles == TLS13_STEPS
    elif config.exchange == "RSA key transport":
        assert titles == [
            t
            for t in TLS12_STEPS
            if t not in ("Server Key Exchange Generation", "Server Key Exchange")
        ]
    else:
        assert titles == TLS12_STEPS
    for s in result["steps"]:
        assert s["description"] and s["inputs"] and s["outputs"]
        assert "{" not in s["description"] + s.get("formula", "")
    assert step(result, "B xác thực tag và giải mã")["outputs"][
        "Khớp thông điệp ban đầu"
    ]
    metrics = result["metrics"]
    assert metrics["plaintext_bytes"] == len(text.encode())
    overhead = 22 if config.version == "TLS 1.3" else 29
    assert metrics["frame_bytes"] == len(text.encode()) + overhead
    json.dumps(result, ensure_ascii=False)


@pytest.mark.parametrize(
    "config", [DemoConfig(), DemoConfig(version="TLS 1.3", exchange="ECDHE X25519")]
)
def test_modified_record_is_rejected_without_plaintext(config):
    result = run_message("A gửi B", config, tamper=True)
    assert result["status"] == "rejected" and result["output"] is None
    last = result["steps"][-1]["outputs"]
    assert last["Kiểm tra auth tag"] == "không hợp lệ"
    assert last["Thông điệp B nhận (UTF-8)"] is None


@pytest.mark.parametrize(
    "config",
    [
        DemoConfig(version="TLS 1.3", exchange="ECDHE X25519"),
        DemoConfig(
            version="TLS 1.3",
            exchange="DHE ffdhe2048",
            cipher="AES-256-GCM",
            hash_name="SHA-384",
        ),
    ],
)
def test_tls13_shown_keys_decrypt_application_record(config):
    result = run_message("Xin chào B", config)
    keys = step(result, "Client Application Keys Calc")["outputs"]
    record = bytes.fromhex(
        step(result, "Client Application Data")["outputs"]["Record đã bọc (hex)"]
    )
    key = bytes.fromhex(keys["client application key (hex)"])
    iv = bytes.fromhex(keys["client application IV (hex)"])
    assert record[:3] == b"\x17\x03\x03"
    inner = AESGCM(key).decrypt(iv, record[5:], record[:5])  # sequence 0
    assert inner == "Xin chào B".encode() + b"\x17"


@pytest.mark.parametrize(
    "config",
    [
        DemoConfig(),
        DemoConfig(exchange="ECDHE P-256", cipher="AES-256-GCM", hash_name="SHA-384"),
    ],
)
def test_tls12_shown_keys_decrypt_application_record(config):
    result = run_message("Xin chào B", config)
    keys = step(result, "Client Encryption Keys Calculation")["outputs"]
    record = bytes.fromhex(
        step(result, "Client Application Data")["outputs"]["Record (hex)"]
    )
    key = bytes.fromhex(keys["client write key (hex)"])
    iv = bytes.fromhex(keys["client write IV, phần cố định (hex)"])
    explicit, protected = record[5:13], record[13:]
    aad = (1).to_bytes(8, "big") + record[:3] + (len(protected) - 16).to_bytes(2, "big")
    assert AESGCM(key).decrypt(iv + explicit, protected, aad) == "Xin chào B".encode()


def test_tls13_shown_ephemeral_keys_reproduce_shared_secret():
    from cryptography.hazmat.primitives.asymmetric import x25519

    result = run_message("A → B", DemoConfig(version="TLS 1.3", exchange="ECDHE X25519"))
    a_private = step(result, "Client Key Exchange Generation")["outputs"][
        "Khóa riêng tạm thời của A (hex)"
    ]
    b_public = step(result, "Server Key Exchange Generation")["outputs"][
        "Khóa công khai tạm thời của B (hex)"
    ]
    secret = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(a_private)
    ).exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(b_public)))
    assert (
        secret.hex()
        == step(result, "Client Handshake Keys Calc")["outputs"]["shared_secret (hex)"]
        == step(result, "Server Handshake Keys Calc")["outputs"]["shared_secret (hex)"]
    )


@pytest.mark.parametrize(
    "config",
    [DemoConfig(), DemoConfig(version="TLS 1.3", exchange="ECDHE X25519", authentication="ECDSA P-256")],
)
def test_exposed_certificate_private_keys_match_certificates(config):
    prepared = run_protocol("A → B", config)["steps"][0]["outputs"]
    assert_key_matches_certificate(
        prepared["Khóa riêng chứng chỉ server (PEM)"],
        prepared["Chứng chỉ server (PEM)"],
    )
    assert_key_matches_certificate(
        prepared["Khóa riêng CA thử nghiệm (PEM)"],
        prepared["Chứng chỉ CA tin cậy (PEM)"],
    )


def test_message_size_limits():
    with pytest.raises(ValueError):
        run_message("", DemoConfig())
    with pytest.raises(ValueError):
        run_message("x" * 32769, DemoConfig())
    with pytest.raises(ValueError):
        run_message("a", DemoConfig(cipher="AES-256-GCM"))


def test_large_message_is_split_into_records():
    text = "x" * 20000
    result = run_message(text, DemoConfig(version="TLS 1.3", exchange="ECDHE X25519"))
    assert result["output"] == text
    assert step(result, "Client Application Data")["outputs"]["Số record"] == 2


def test_web_api_runs_model_and_rejects_missing_token():
    import re
    import threading
    import urllib.error
    import urllib.request
    from dataclasses import asdict

    from ssl_tls_lab.web_server import make_server

    server = make_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        page = urllib.request.urlopen(base, timeout=5).read().decode()
        assert 'id="mode"' not in page
        token = re.search(r'window.LAB_TOKEN="([0-9a-f]+)"', page).group(1)
        data = json.dumps(
            {"message": "Xin chào B", "config": asdict(DemoConfig()), "tamper": False}
        ).encode()
        req = urllib.request.Request(
            base + "/api/message",
            data,
            headers={"Content-Type": "application/json", "X-Lab-Token": token},
        )
        result = json.loads(urllib.request.urlopen(req, timeout=10).read())
        assert result["output"] == "Xin chào B"
        assert result["steps"][1]["title"] == "Client Hello"
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(
                urllib.request.Request(base + "/api/message", b"{}"), timeout=5
            )
        assert error.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_cli_writes_private_json(tmp_path):
    import subprocess
    import sys

    output = tmp_path / "secret.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "ssl_tls_lab",
            "message",
            "--version",
            "TLS 1.3",
            "--text",
            "A → B",
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600
    result = json.loads(output.read_text(encoding="utf-8"))
    assert [s["title"] for s in result["steps"]] == TLS13_STEPS


# --- Legacy backend (SSL 2.0 – TLS 1.1) ------------------------------------


@pytest.mark.parametrize(
    "config",
    [
        DemoConfig(version="SSL 2.0", cipher="RC4-128", hash_name="MD5"),
        DemoConfig(version="SSL 2.0", cipher="3DES-CBC", hash_name="MD5"),
        DemoConfig(version="SSL 3.0", cipher="RC4-128", hash_name="MD5"),
        DemoConfig(version="SSL 3.0", cipher="3DES-CBC", hash_name="SHA-1"),
        DemoConfig(version="TLS 1.0", cipher="AES-128-CBC", hash_name="SHA-1"),
        DemoConfig(
            version="TLS 1.0",
            exchange="ECDHE P-256",
            cipher="AES-256-CBC",
            hash_name="SHA-1",
        ),
        DemoConfig(version="TLS 1.1", cipher="AES-256-CBC", hash_name="SHA-1"),
        DemoConfig(
            version="TLS 1.1",
            exchange="ECDHE P-256",
            cipher="AES-128-CBC",
            hash_name="SHA-1",
        ),
        DemoConfig(
            version="TLS 1.0",
            exchange="DHE 2048",
            cipher="AES-128-CBC",
            hash_name="SHA-1",
        ),
        DemoConfig(
            version="TLS 1.1",
            exchange="DHE 2048",
            cipher="AES-256-CBC",
            hash_name="SHA-1",
        ),
        DemoConfig(
            version="TLS 1.0",
            exchange="ECDHE P-256",
            authentication="ECDSA P-256",
            cipher="AES-128-CBC",
            hash_name="SHA-1",
        ),
        DemoConfig(
            version="TLS 1.1",
            exchange="ECDHE P-256",
            authentication="ECDSA P-256",
            cipher="AES-256-CBC",
            hash_name="SHA-1",
        ),
    ],
)
def test_legacy_isolated_real_protocol(config):
    import shutil, subprocess
    from ssl_tls_lab.protocols import run_protocol

    if (
        not shutil.which("docker")
        or subprocess.run(
            ["docker", "image", "inspect", "ssl-tls-lab:legacy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
    ):
        pytest.skip("Legacy Docker image unavailable")
    result = run_protocol("Chào B!", config)
    assert result["status"] == "success" and result["output"] == "Chào B!"
    assert all(step["inputs"] and step["outputs"] for step in result["steps"])
    assert all("Đầu vào" not in step["inputs"] for step in result["steps"])
    assert result["metrics"]["encrypt_ms"] is None
    assert any("wire_hex" in step["details"] for step in result["steps"])
    assert any(s["details"].get("protocol") == config.version for s in result["steps"])
    assert result["steps"][-1]["details"]["authentication"] == config.authentication
    prepared = result["steps"][0]["outputs"]
    assert_key_matches_certificate(
        prepared["Khóa riêng chứng chỉ server (PEM)"],
        prepared["Chứng chỉ server (PEM)"],
    )
    assert "A là server" in result["steps"][0]["context"]["roles"]
    assert (
        "A (server)"
        in result["steps"][0]["explanations"]["outputs"][
            "Khóa riêng chứng chỉ server (PEM)"
        ]["location"]
    )
    if config.exchange != "RSA key transport":
        assert result["steps"][-1]["details"]["observed_group"] == config.exchange


def test_ssl1_is_history_only_and_legacy_tamper_is_explicit():
    from ssl_tls_lab.protocols import run_protocol

    with pytest.raises(ValueError, match="SSL 1.0"):
        run_protocol("A", DemoConfig(version="SSL 1.0"))
    with pytest.raises(ValueError, match="sửa record"):
        run_protocol(
            "A",
            DemoConfig(version="SSL 2.0", cipher="RC4-128", hash_name="MD5"),
            tamper=True,
        )


@pytest.mark.parametrize(
    "config",
    [
        DemoConfig(exchange="RSA key transport", authentication="ECDSA P-256"),
        DemoConfig(exchange="DHE 2048", authentication="ECDSA P-256"),
        DemoConfig(version="TLS 1.3", exchange="DHE 2048"),
        DemoConfig(
            version="SSL 3.0",
            exchange="RSA key transport",
            authentication="ECDSA P-256",
            cipher="3DES-CBC",
            hash_name="SHA-1",
        ),
    ],
)
def test_unsupported_exchange_auth_pairs_are_rejected(config):
    with pytest.raises(ValueError):
        config.validate()


