import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ssl_tls_lab.message_demo import DemoConfig, run_message


def assert_key_matches_certificate(private_pem, certificate_pem):
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())

    def public_bytes(public):
        return public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    assert public_bytes(key.public_key()) == public_bytes(cert.public_key())


@pytest.mark.parametrize(
    "config",
    [
        DemoConfig(),
        DemoConfig(exchange="ECDHE X25519"),
        DemoConfig(
            version="TLS 1.3",
            exchange="ECDHE X25519",
            cipher="AES-256-GCM",
            hash_name="SHA-384",
        ),
    ],
)
def test_message_reaches_b_over_tcp_and_keys_match(config):
    text = "Chào B! 🔐 こんにちは"
    result = run_message(text, config)
    assert result["status"] == "success" and result["output"] == text
    assert result["metrics"]["plaintext_bytes"] == len(text.encode("utf-8"))
    assert result["metrics"]["frame_bytes"] == len(text.encode("utf-8")) + 32
    keys = next(
        s for s in result["steps"] if s["title"] == "Dẫn xuất khóa phiên độc lập"
    )
    assert keys["details"]["keys_match"] is True
    assert keys["details"]["A_to_B_key_A"] == keys["details"]["A_to_B_key_B"]
    assert result["steps"][-1]["details"]["matches_original"] is True
    json.dumps(result, ensure_ascii=False)


def test_modified_tag_is_rejected_without_plaintext():
    result = run_message("A gửi B", DemoConfig(exchange="ECDHE X25519"), tamper=True)
    assert result["status"] == "rejected" and result["output"] is None
    assert result["steps"][-1]["details"]["tag"] == "không hợp lệ"
    assert result["steps"][-1]["details"]["plaintext_utf8"] is None


def test_rejects_incompatible_config_and_oversize():
    with pytest.raises(ValueError):
        run_message("a", DemoConfig(version="TLS 1.3"))
    with pytest.raises(ValueError):
        run_message("a", DemoConfig(cipher="AES-256-GCM"))
    with pytest.raises(ValueError):
        run_message("x" * 32769, DemoConfig())


@pytest.mark.parametrize("exchange", ["RSA key transport", "ECDHE X25519"])
def test_real_tls12_handshake_transfer_and_tamper(exchange):
    from ssl_tls_lab.real_tls import run_real_tls

    cfg = DemoConfig(exchange=exchange)
    result = run_real_tls("Xin chào B", cfg)
    assert result["status"] == "success" and result["output"] == "Xin chào B"
    negotiated = next(
        s for s in result["steps"] if s["title"] == "Handshake TLS hoàn tất"
    )
    assert negotiated["details"]["version"] == "TLSv1.2"
    assert negotiated["details"]["cipher"] == (
        "ECDHE-RSA-AES128-GCM-SHA256"
        if exchange.startswith("ECDHE")
        else "AES128-GCM-SHA256"
    )
    wire = next(
        s for s in result["steps"] if s["title"] == "Truyền TLS record qua TCP loopback"
    )
    assert bytes.fromhex(wire["details"]["wire_hex"])[0] == 23
    rejected = run_real_tls("Xin chào B", cfg, tamper=True)
    assert rejected["status"] == "rejected" and rejected["output"] is None


def test_web_api_both_modes_and_rejects_missing_token():
    import re
    import threading
    import urllib.error
    import urllib.request
    from ssl_tls_lab.web_server import make_server

    server = make_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        page = urllib.request.urlopen(base, timeout=5).read().decode()
        token = re.search(r'window.LAB_TOKEN="([0-9a-f]+)"', page).group(1)
        from dataclasses import asdict

        for mode in ("model", "real"):
            data = json.dumps(
                {
                    "mode": mode,
                    "message": "Xin chào B",
                    "config": asdict(DemoConfig()),
                    "tamper": False,
                }
            ).encode()
            req = urllib.request.Request(
                base + "/api/message",
                data,
                headers={"Content-Type": "application/json", "X-Lab-Token": token},
            )
            result = json.loads(urllib.request.urlopen(req, timeout=5).read())
            assert result["mode"] == mode and result["output"] == "Xin chào B"
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(
                urllib.request.Request(base + "/api/message", b"{}"), timeout=5
            )
        assert error.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


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


@pytest.mark.parametrize(
    "cipher,hash_name,actual",
    [
        ("AES-128-GCM", "SHA-256", "TLS_AES_128_GCM_SHA256"),
        ("AES-256-GCM", "SHA-384", "TLS_AES_256_GCM_SHA384"),
    ],
)
def test_tls13_real_pins_requested_cipher_and_rejects_tamper(cipher, hash_name, actual):
    from ssl_tls_lab.protocols import run_protocol

    cfg = DemoConfig(
        version="TLS 1.3", exchange="ECDHE X25519", cipher=cipher, hash_name=hash_name
    )
    for tamper in (False, True):
        result = run_protocol("Xin chào B", cfg, tamper)
        assert result["status"] == ("rejected" if tamper else "success")
        assert (result["output"] is None) == tamper
        observed = next(
            s for s in result["steps"] if s["title"] == "Handshake TLS hoàn tất"
        )
        assert (
            observed["details"]["version"] == "TLSv1.3"
            and observed["details"]["cipher"] == actual
        )


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
    "version,exchange,auth",
    [
        ("TLS 1.2", "DHE 2048", "RSA"),
        ("TLS 1.2", "ECDHE X25519", "RSA"),
        ("TLS 1.2", "ECDHE P-256", "RSA"),
        ("TLS 1.2", "ECDHE X25519", "ECDSA P-256"),
        ("TLS 1.2", "ECDHE P-256", "ECDSA P-256"),
        ("TLS 1.3", "ECDHE X25519", "RSA"),
        ("TLS 1.3", "ECDHE P-256", "RSA"),
        ("TLS 1.3", "ECDHE X25519", "ECDSA P-256"),
        ("TLS 1.3", "ECDHE P-256", "ECDSA P-256"),
        ("TLS 1.3", "DHE ffdhe2048", "RSA"),
        ("TLS 1.3", "DHE ffdhe2048", "ECDSA P-256"),
    ],
)
@pytest.mark.parametrize(
    "cipher,hash_name", [("AES-128-GCM", "SHA-256"), ("AES-256-GCM", "SHA-384")]
)
def test_real_handshake_checks_selected_group_and_authentication(
    version, exchange, auth, cipher, hash_name
):
    from ssl_tls_lab.protocols import run_protocol

    config = DemoConfig(
        version=version,
        exchange=exchange,
        authentication=auth,
        cipher=cipher,
        hash_name=hash_name,
    )
    result = run_protocol("Thông điệp A → B", config)
    assert result["status"] == "success" and result["output"] == "Thông điệp A → B"
    handshake = next(
        step["details"]
        for step in result["steps"]
        if step["title"] == "Handshake TLS hoàn tất"
    )
    assert handshake["observed_group"] == exchange
    assert handshake["authentication"] == auth
    if version == "TLS 1.2":
        assert handshake["cipher"].startswith(
            "ECDHE-ECDSA-"
            if auth.startswith("ECDSA")
            else "DHE-RSA-"
            if exchange.startswith("DHE")
            else "ECDHE-RSA-"
        )


@pytest.mark.parametrize(
    "exchange,auth",
    [
        ("DHE 2048", "RSA"),
        ("ECDHE X25519", "ECDSA P-256"),
        ("ECDHE P-256", "ECDSA P-256"),
    ],
)
def test_model_cryptographic_steps_match_and_reject_tampering(exchange, auth):
    config = DemoConfig(exchange=exchange, authentication=auth)
    good = run_message("Xin chào B", config)
    assert good["output"] == "Xin chào B"
    assert next(
        step["details"]["matches"]
        for step in good["steps"]
        if step["title"] == "Kiểm tra chữ ký và tính bí mật chung"
    )
    bad = run_message("Xin chào B", config, tamper=True)
    assert bad["status"] == "rejected" and bad["output"] is None


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


@pytest.mark.parametrize("auth", ["RSA", "ECDSA P-256"])
def test_model_tls13_ffdhe2048(auth):
    config = DemoConfig(
        version="TLS 1.3", exchange="DHE ffdhe2048", authentication=auth
    )
    result = run_message("Xin chào B", config)
    assert result["output"] == "Xin chào B"
    assert next(
        s["details"]["matches"]
        for s in result["steps"]
        if s["title"] == "Kiểm tra chữ ký và tính bí mật chung"
    )


def test_model_step_inputs_outputs_follow_actual_message_and_tampered_tag():
    from ssl_tls_lab.protocols import run_protocol

    config = DemoConfig(
        version="TLS 1.3", exchange="DHE ffdhe2048", authentication="ECDSA P-256"
    )
    result = run_protocol("Xin chào B", config, tamper=True, mode="model")
    assert all(step["inputs"] and step["outputs"] for step in result["steps"])
    assert all("Đầu vào" not in step["inputs"] for step in result["steps"])
    enc = next(s for s in result["steps"] if s["title"] == "AES-GCM mã hóa và tạo tag")
    sign = next(s for s in result["steps"] if s["title"] == "B ký khóa tạm thời")
    kdf = next(
        s for s in result["steps"] if s["title"] == "Dẫn xuất khóa phiên độc lập"
    )
    transfer = next(
        s for s in result["steps"] if s["title"] == "Truyền bản mã qua TCP loopback"
    )
    dec = next(s for s in result["steps"] if s["title"] == "Kiểm tra tag và giải mã")
    assert enc["inputs"]["Thông điệp (UTF-8)"] == "Xin chào B"
    assert (
        sign["inputs"]["Dữ liệu được ký (hex)"]
        == sign["inputs"]["Client random (hex)"]
        + sign["inputs"]["Server random (hex)"]
        + sign["outputs"]["Khóa công khai tạm thời của B (hex)"]
    )
    assert len(kdf["inputs"]["HKDF salt (hex)"]) == 64
    assert transfer["inputs"]["Tag gốc (hex)"] == enc["outputs"]["Tag xác thực (hex)"]
    assert dec["inputs"]["Tag nhận được (hex)"] != enc["outputs"]["Tag xác thực (hex)"]
    assert dec["outputs"]["Bản rõ nhận được (UTF-8)"] is None
    assert dec["outputs"]["Kết quả kiểm tra tag"] == "không hợp lệ"


def test_real_tls_step_inputs_outputs_contain_observed_record_and_no_invented_key():
    from ssl_tls_lab.protocols import run_protocol

    config = DemoConfig(exchange="ECDHE X25519", authentication="ECDSA P-256")
    result = run_protocol("Xin chào B", config, tamper=True)
    assert all(step["inputs"] and step["outputs"] for step in result["steps"])
    assert all("Đầu vào" not in step["inputs"] for step in result["steps"])
    enc = next(
        s
        for s in result["steps"]
        if s["title"] == "Mã hóa thành TLS application record"
    )
    transfer = next(
        s for s in result["steps"] if s["title"] == "Truyền TLS record qua TCP loopback"
    )
    dec = next(
        s for s in result["steps"] if s["title"] == "Xác thực và giải mã TLS record"
    )
    assert "chưa trích xuất" in enc["inputs"]["Khóa phiên"].lower()
    record = bytes.fromhex(enc["outputs"]["TLS application record (hex)"])
    assert enc["outputs"]["Nonce tường minh của record (hex)"] == record[5:13].hex()
    assert enc["outputs"]["Tag xác thực GCM (hex)"] == record[-16:].hex()
    assert (
        transfer["inputs"]["TLS record trước khi truyền (hex)"]
        == enc["outputs"]["TLS application record (hex)"]
    )
    assert (
        transfer["outputs"]["TLS record sau khi truyền (hex)"]
        == dec["inputs"]["TLS record nhận được (hex)"]
    )
    assert (
        transfer["inputs"]["TLS record trước khi truyền (hex)"]
        != transfer["outputs"]["TLS record sau khi truyền (hex)"]
    )
    assert dec["outputs"]["Thông điệp nhận (UTF-8)"] is None


def test_real_rsa_components_are_from_certificate_key():
    import math
    from ssl_tls_lab.protocols import run_protocol

    prepared = run_protocol("A → B", DemoConfig(), mode="real")["steps"][0]
    key = serialization.load_pem_private_key(
        prepared["outputs"]["Khóa riêng chứng chỉ server (PEM)"].encode(), None
    ).private_numbers()
    generation, relation = prepared["operations"][:2]
    assert int(generation["outputs"]["Số nguyên tố bí mật p (hex)"], 16) == key.p
    assert int(generation["outputs"]["Số nguyên tố bí mật q (hex)"], 16) == key.q
    assert (
        int(relation["outputs"]["Modulus n = p × q (hex)"], 16) == key.public_numbers.n
    )
    assert int(relation["outputs"]["Số mũ bí mật d (hex)"], 16) == key.d
    assert key.public_numbers.e * key.d % math.lcm(key.p - 1, key.q - 1) == 1


@pytest.mark.parametrize(
    "mode,config",
    [
        ("real", DemoConfig()),
        ("real", DemoConfig(exchange="ECDHE P-256", authentication="ECDSA P-256")),
        (
            "real",
            DemoConfig(
                version="TLS 1.3", exchange="ECDHE X25519", authentication="ECDSA P-256"
            ),
        ),
        ("model", DemoConfig(exchange="ECDHE X25519", authentication="ECDSA P-256")),
    ],
)
def test_exposed_certificate_private_keys_match_certificates(mode, config):
    from ssl_tls_lab.protocols import run_protocol

    prepared = run_protocol("A → B", config, mode=mode)["steps"][0]["outputs"]
    assert_key_matches_certificate(
        prepared["Khóa riêng chứng chỉ server (PEM)"],
        prepared["Chứng chỉ server (PEM)"],
    )
    assert_key_matches_certificate(
        prepared["Khóa riêng CA thí nghiệm (PEM)"],
        prepared["Chứng chỉ CA tin cậy (PEM)"],
    )


@pytest.mark.parametrize("exchange", ["DHE 2048", "ECDHE X25519", "ECDHE P-256"])
def test_model_exposed_ephemeral_keys_reproduce_shared_secret(exchange):
    from ssl_tls_lab.protocols import run_protocol

    result = run_protocol("A → B", DemoConfig(exchange=exchange), mode="model")
    signed = next(s for s in result["steps"] if s["title"] == "B ký khóa tạm thời")
    shared = next(
        s
        for s in result["steps"]
        if s["title"] == "Kiểm tra chữ ký và tính bí mật chung"
    )
    a = serialization.load_pem_private_key(
        signed["outputs"]["Khóa riêng tạm thời của A (PEM)"].encode(), password=None
    )
    b = serialization.load_pem_private_key(
        signed["outputs"]["Khóa riêng tạm thời của B (PEM)"].encode(), password=None
    )
    secret = (
        a.exchange(ec.ECDH(), b.public_key())
        if exchange == "ECDHE P-256"
        else a.exchange(b.public_key())
    )
    assert (
        secret.hex()
        == shared["outputs"]["Bí mật chung của A (hex)"]
        == shared["outputs"]["Bí mật chung của B (hex)"]
    )
    assert (
        shared["inputs"]["Khóa riêng tạm thời của A (PEM)"]
        == signed["outputs"]["Khóa riêng tạm thời của A (PEM)"]
    )


def test_cli_private_json_has_restricted_permissions(tmp_path):
    import subprocess, sys

    output = tmp_path / "secret.json"
    output.write_text("old", encoding="utf-8")
    output.chmod(0o644)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "ssl_tls_lab",
            "message",
            "--text",
            "A → B",
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.stat().st_mode & 0o777 == 0o600
    prepared = json.loads(output.read_text(encoding="utf-8"))["steps"][0]["outputs"]
    assert_key_matches_certificate(
        prepared["Khóa riêng chứng chỉ server (PEM)"],
        prepared["Chứng chỉ server (PEM)"],
    )


@pytest.mark.parametrize("mode", ["real", "model"])
def test_step_explanations_cover_all_inputs_and_outputs(mode):
    from ssl_tls_lab.protocols import run_protocol

    result = run_protocol("A → B", DemoConfig(exchange="ECDHE P-256"), mode=mode)
    for step in result["steps"]:
        assert "A là client" in step["context"]["roles"]
        for section in ("inputs", "outputs"):
            assert set(step["explanations"][section]) == set(step[section])
            for explanation in step["explanations"][section].values():
                assert all(
                    explanation[field] for field in ("location", "origin", "purpose")
                )
    prepared = result["steps"][0]["explanations"]["outputs"][
        "Khóa riêng chứng chỉ server (PEM)"
    ]
    assert "B (server)" in prepared["location"]
    assert "không" in prepared["location"].lower()
    if mode == "real":
        handshake = next(
            s for s in result["steps"] if s["title"] == "Handshake TLS hoàn tất"
        )
        assert (
            "không trích xuất"
            in handshake["explanations"]["outputs"]["Khóa riêng DH/ECDHE tạm thời"][
                "origin"
            ]
        )
    else:
        signed = next(s for s in result["steps"] if s["title"] == "B ký khóa tạm thời")
        assert (
            "sinh mới"
            in signed["explanations"]["outputs"]["Khóa riêng tạm thời của A (PEM)"][
                "origin"
            ].lower()
        )
