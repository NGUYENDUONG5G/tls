"""Select the appropriate isolated backend for a message exchange."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from .message_demo import DemoConfig, run_message


def run_protocol(message: str, config: DemoConfig, tamper=False, mode="real") -> dict:
    config.validate()
    if mode == "model":
        result = run_message(message, config, tamper)
    elif mode != "real":
        raise ValueError("Chế độ không hợp lệ.")
    elif config.version in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
        from .legacy_tls import run_legacy_tls

        result = run_legacy_tls(message, config, tamper)
    elif config.version == "TLS 1.3" or (
        config.version == "TLS 1.2"
        and config.exchange == "ECDHE X25519"
        and config.authentication == "ECDSA P-256"
    ):
        # Configure a fresh process before importing ssl: this allows TLS 1.3
        # cipher/group selection and TLS 1.2 ECDSA/X25519 with its signing curve.
        # Verify the actual negotiated suite and group; never alter the parent.
        suite = (
            "TLS_AES_128_GCM_SHA256"
            if config.cipher == "AES-128-GCM"
            else "TLS_AES_256_GCM_SHA384"
        )
        with tempfile.TemporaryDirectory(prefix="tls13-conf-") as tmp:
            conf = Path(tmp) / "openssl.cnf"
            setting = (
                "Ciphersuites = "
                + suite
                + (
                    "\nGroups = ffdhe2048:P-256"
                    if config.exchange == "DHE ffdhe2048"
                    else ""
                )
                if config.version == "TLS 1.3"
                else "Groups = X25519:P-256"
            )
            conf.write_text(
                "openssl_conf = default_conf\n[default_conf]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\n"
                + setting
                + "\n"
            )
            env = {**os.environ, "OPENSSL_CONF": str(conf)}
            request = json.dumps(
                {"message": message, "config": asdict(config), "tamper": tamper},
                ensure_ascii=False,
            )
            try:
                process = subprocess.run(
                    [sys.executable, "-m", "ssl_tls_lab.openssl_worker"],
                    input=request,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Worker TLS hết thời gian chờ.") from exc
            try:
                response = json.loads(process.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Không khởi động được worker TLS: " + process.stderr[-1000:]
                ) from exc
            if not response.get("ok"):
                raise RuntimeError(response.get("error", "TLS thất bại"))
            result = response["result"]
            result["limitations"].append(
                "Dùng OpenSSL config riêng trong tiến trình con để giới hạn suite/nhóm; thời gian khởi động tiến trình con không nằm trong metric."
            )
    else:
        from .real_tls import run_real_tls

        result = run_real_tls(message, config, tamper)
    result["mode"] = mode
    from .step_io import annotate_steps
    from .explanations import explain_steps

    return explain_steps(annotate_steps(result))
