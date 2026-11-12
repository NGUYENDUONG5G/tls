"""Select the backend for a message exchange."""

from __future__ import annotations

from .message_demo import DemoConfig, run_message

LEGACY = ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")


def run_protocol(message: str, config: DemoConfig, tamper=False) -> dict:
    """TLS 1.2/1.3 run the step-by-step model; older versions run in the container."""
    config.validate()
    if config.version not in LEGACY:
        return run_message(message, config, tamper)
    from .explanations import explain_steps
    from .legacy_tls import run_legacy_tls
    from .step_io import annotate_steps

    return explain_steps(annotate_steps(run_legacy_tls(message, config, tamper)))
