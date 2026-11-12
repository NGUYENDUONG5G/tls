"""Run one historical SSL exchange inside the network-isolated legacy image."""

import base64
import json
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

OPENSSL = "/opt/openssl/bin/openssl"


def run(request):
    version = request["version"]
    cipher = request["cipher"]
    payload = base64.b64decode(request["message_base64"], validate=True)
    allowed = {
        "SSL 2.0": {"RC4-MD5", "DES-CBC3-MD5"},
        "SSL 3.0": {"RC4-MD5", "DES-CBC3-SHA"},
        "TLS 1.0": {
            "AES128-SHA",
            "AES256-SHA",
            "DHE-RSA-AES128-SHA",
            "DHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-ECDSA-AES256-SHA",
        },
        "TLS 1.1": {
            "AES128-SHA",
            "AES256-SHA",
            "DHE-RSA-AES128-SHA",
            "DHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-ECDSA-AES256-SHA",
        },
    }
    if (
        version not in allowed
        or cipher not in allowed[version]
        or not 1 <= len(payload) <= 16000
    ):
        raise ValueError("Tổ hợp SSL hoặc kích thước thông điệp không hợp lệ")
    flag = {
        "SSL 2.0": "-ssl2",
        "SSL 3.0": "-ssl3",
        "TLS 1.0": "-tls1",
        "TLS 1.1": "-tls1_1",
    }[version]
    start = time.perf_counter_ns()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        prep = time.perf_counter_ns()
        auth = request.get("authentication", "RSA")
        if auth == "ECDSA P-256":
            subprocess.run(
                [
                    OPENSSL,
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                    "server.key",
                ],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                timeout=30,
            )
            create_cert = [
                OPENSSL,
                "req",
                "-x509",
                "-new",
                "-key",
                "server.key",
                "-out",
                "server.pem",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-sha256",
            ]
        elif auth == "RSA":
            create_cert = [
                OPENSSL,
                "req",
                "-x509",
                "-newkey",
                f"rsa:{request['rsa_bits']}",
                "-keyout",
                "server.key",
                "-out",
                "server.pem",
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-sha256",
            ]
        else:
            raise ValueError("Thuật toán xác thực không hợp lệ")
        subprocess.run(
            create_cert,
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
        (root / "message.bin").write_bytes(payload)
        prep_ms = (time.perf_counter_ns() - prep) / 1e6
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        group_server = ["-named_curve", "P-256"] if cipher.startswith("ECDHE") else []
        if cipher.startswith("DHE-"):
            (root / "dh.pem").write_text(request["dh_pem"])
            group_server += ["-dhparam", "dh.pem"]
        server = subprocess.Popen(
            [
                OPENSSL,
                "s_server",
                "-accept",
                str(port),
                flag,
                "-cipher",
                cipher,
                *group_server,
                "-cert",
                "server.pem",
                "-key",
                "server.key",
                "-WWW",
                "-no_comp",
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        captures = []
        proxy_errors = []
        ready = threading.Event()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            proxy_port = listener.getsockname()[1]

            def proxy():
                try:
                    ready.set()
                    with (
                        listener.accept()[0] as client,
                        socket.create_connection(
                            ("127.0.0.1", port), timeout=5
                        ) as upstream,
                    ):
                        client.setblocking(False)
                        upstream.setblocking(False)
                        peers = {
                            client: (upstream, "B → A"),
                            upstream: (client, "A → B"),
                        }
                        end = time.monotonic() + 20
                        while time.monotonic() < end:
                            readable, _, _ = select.select(list(peers), [], [], 0.2)
                            for source in readable:
                                try:
                                    chunk = source.recv(65536)
                                except BlockingIOError:
                                    continue
                                if not chunk:
                                    return
                                target, direction = peers[source]
                                captures.append(
                                    {
                                        "direction": direction,
                                        "bytes": len(chunk),
                                        "wire_hex": chunk.hex(),
                                        "offset_ms": (time.perf_counter_ns() - start)
                                        / 1e6,
                                    }
                                )
                                target.setblocking(True)
                                target.sendall(chunk)
                                target.setblocking(False)
                except Exception as exc:
                    proxy_errors.append(str(exc))

            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError("SSL server dừng sớm")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.03)
                else:
                    raise RuntimeError("SSL server không khởi động")
                thread = threading.Thread(target=proxy, daemon=True)
                thread.start()
                ready.wait(2)
                group_client = (
                    ["-curves", "P-256"] if cipher.startswith("ECDHE") else []
                )
                args = [
                    OPENSSL,
                    "s_client",
                    "-connect",
                    f"127.0.0.1:{proxy_port}",
                    flag,
                    "-cipher",
                    cipher,
                    *group_client,
                    "-CAfile",
                    "server.pem",
                    "-verify_return_error",
                    "-verify_hostname",
                    "localhost",
                    "-ign_eof",
                ]
                tick = time.perf_counter_ns()
                client = subprocess.run(
                    args,
                    input=b"GET /message.bin HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    cwd=root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=25,
                )
                elapsed = (time.perf_counter_ns() - tick) / 1e6
                thread.join(3)
                if client.returncode:
                    raise RuntimeError(
                        "SSL client lỗi: "
                        + client.stderr.decode(errors="replace")[-3000:]
                    )
                marker = b"HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n"
                prefix, separator, body = client.stdout.partition(marker)
                if (
                    not separator
                    or body[: len(payload)] != payload
                    or body[len(payload) :] not in (b"", b"closed\n")
                ):
                    raise RuntimeError(
                        "Không nhận đúng HTTP payload; received=" + str(len(body))
                    )
                text = prefix.decode(errors="replace")
                observed_protocol = re.search(
                    r"^\s*Protocol\s*:\s*(\S+)", text, re.MULTILINE
                )
                observed_cipher = re.search(
                    r"^\s*Cipher\s*:\s*(\S+)", text, re.MULTILINE
                )
                verification = re.search(
                    r"^\s*Verify return code:\s*0\s*\(ok\)", text, re.MULTILINE
                )
                expected_protocol = {
                    "SSL 2.0": "SSLv2",
                    "SSL 3.0": "SSLv3",
                    "TLS 1.0": "TLSv1",
                    "TLS 1.1": "TLSv1.1",
                }[version]
                if (
                    not observed_protocol
                    or observed_protocol.group(1) != expected_protocol
                    or not observed_cipher
                    or observed_cipher.group(1) != cipher
                    or not verification
                ):
                    raise RuntimeError(
                        "Thương lượng hoặc xác minh chứng chỉ không khớp yêu cầu"
                    )
                if proxy_errors:
                    raise RuntimeError("Proxy: " + str(proxy_errors))
                return {
                    "version": version,
                    "cipher": cipher,
                    "observed_protocol": observed_protocol.group(1),
                    "observed_cipher": observed_cipher.group(1),
                    "verify_return": "0 (ok)",
                    "message_base64": base64.b64encode(body[: len(payload)]).decode(),
                    "cert_pem": (root / "server.pem").read_text(),
                    "server_private_key_pem": (root / "server.key").read_text(),
                    "client_stderr": client.stderr.decode(errors="replace"),
                    "captures": captures,
                    "prep_ms": prep_ms,
                    "transfer_elapsed_ms": elapsed,
                    "total_ms": (time.perf_counter_ns() - start) / 1e6,
                    "openssl": "OpenSSL 1.0.2u",
                    "network": "Docker --network none; loopback nội bộ",
                }
            finally:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    try:
        print(
            json.dumps(
                {"ok": True, "result": run(json.load(sys.stdin))}, ensure_ascii=False
            )
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        sys.exit(1)
