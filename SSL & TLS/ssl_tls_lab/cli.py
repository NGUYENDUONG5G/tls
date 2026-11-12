from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from .message_demo import DemoConfig
from .protocols import run_protocol

VERSIONS = ("SSL 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
DEFAULTS = {
    "SSL 2.0": ("RSA key transport", "RC4-128", "MD5"),
    "SSL 3.0": ("RSA key transport", "RC4-128", "MD5"),
    "TLS 1.0": ("RSA key transport", "AES-128-CBC", "SHA-1"),
    "TLS 1.1": ("RSA key transport", "AES-128-CBC", "SHA-1"),
    "TLS 1.2": ("RSA key transport", "AES-128-GCM", "SHA-256"),
    "TLS 1.3": ("ECDHE X25519", "AES-128-GCM", "SHA-256"),
}


def parser():
    main = argparse.ArgumentParser(
        description="Minh họa một thông điệp A → B qua SSL/TLS"
    )
    commands = main.add_subparsers(dest="command", required=True)
    gui = commands.add_parser("gui", help="Mở giao diện trình duyệt tại máy cục bộ")
    gui.add_argument("--port", type=int, default=0)
    gui.add_argument("--no-browser", action="store_true")
    commands.add_parser("doctor", help="Kiểm tra Python, OpenSSL và container legacy")
    commands.add_parser("versions", help="Liệt kê phiên bản và khả năng chạy")
    commands.add_parser("lab-build", help="Build image SSL/TLS cũ từ OpenSSL 1.0.2u")
    message = commands.add_parser(
        "message", help="Chạy một thông điệp và xuất log JSON"
    )
    message.add_argument("--text", required=True)
    message.add_argument("--mode", choices=("real", "model"), default="real")
    message.add_argument("--version", choices=VERSIONS, default="TLS 1.2")
    message.add_argument(
        "--exchange",
        choices=(
            "RSA key transport",
            "DHE 2048",
            "DHE ffdhe2048",
            "ECDHE P-256",
            "ECDHE X25519",
        ),
    )
    message.add_argument(
        "--authentication", choices=("RSA", "ECDSA P-256"), default="RSA"
    )
    message.add_argument(
        "--cipher",
        choices=(
            "RC4-128",
            "3DES-CBC",
            "AES-128-CBC",
            "AES-256-CBC",
            "AES-128-GCM",
            "AES-256-GCM",
        ),
    )
    message.add_argument("--hash", choices=("MD5", "SHA-1", "SHA-256", "SHA-384"))
    message.add_argument("--rsa-bits", type=int, choices=(2048, 3072), default=2048)
    message.add_argument("--tamper", action="store_true")
    message.add_argument("--output", type=Path)
    return main


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "gui":
            from .web_server import main as web_main

            web_main(args.port, not args.no_browser)
        elif args.command == "doctor":
            docker = shutil.which("docker")
            info = {
                "python": sys.version.split()[0],
                "openssl": ssl.OPENSSL_VERSION,
                "cryptography": importlib.util.find_spec("cryptography") is not None,
                "docker": bool(docker),
                "legacy_image": False,
            }
            if docker:
                check = subprocess.run(
                    [docker, "image", "inspect", "ssl-tls-lab:legacy"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                info["legacy_image"] = check.returncode == 0
            print(json.dumps(info, ensure_ascii=False, indent=2))
        elif args.command == "versions":
            for version in VERSIONS:
                print(
                    f"{version}\t"
                    + (
                        "lịch sử; chưa có triển khai công khai được xác minh"
                        if version == "SSL 1.0"
                        else "kết nối thực"
                    )
                )
        elif args.command == "lab-build":
            root = Path(__file__).resolve().parent.parent
            subprocess.run(
                [
                    "docker",
                    "build",
                    "-f",
                    str(root / "lab/Dockerfile"),
                    "-t",
                    "ssl-tls-lab:legacy",
                    "--build-arg",
                    "OPENSSL_VERSION=1.0.2u",
                    "--build-arg",
                    "OPENSSL_SHA256=ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16",
                    str(root),
                ],
                check=True,
            )
        elif args.command == "message":
            if args.version == "SSL 1.0":
                raise ValueError(
                    "SSL 1.0 chỉ có dữ liệu lịch sử; chưa có triển khai công khai được xác minh."
                )
            exchange, cipher, hash_name = DEFAULTS[args.version]
            cipher = args.cipher or cipher
            if args.cipher and not args.hash:
                mapping = {
                    "RC4-128": "MD5",
                    "3DES-CBC": "MD5" if args.version == "SSL 2.0" else "SHA-1",
                    "AES-128-CBC": "SHA-1",
                    "AES-256-CBC": "SHA-1",
                    "AES-128-GCM": "SHA-256",
                    "AES-256-GCM": "SHA-384",
                }
                hash_name = mapping[cipher]
            config = DemoConfig(
                args.version,
                args.exchange or exchange,
                args.authentication,
                cipher,
                args.hash or hash_name,
                args.rsa_bits,
            )
            result = run_protocol(args.text, config, args.tamper, args.mode)
            text = json.dumps(result, ensure_ascii=False, indent=2)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    os.fchmod(output.fileno(), 0o600)
                    output.write(text + "\n")
                print(args.output)
            else:
                print(text)
            return 0 if result["status"] == "success" else 1
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
