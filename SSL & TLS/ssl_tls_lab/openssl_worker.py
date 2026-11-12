"""Fresh process whose OpenSSL configuration constrains TLS choices."""

import json
import sys

from .message_demo import DemoConfig
from .real_tls import run_real_tls

try:
    request = json.load(sys.stdin)
    result = run_real_tls(
        request["message"],
        DemoConfig(**request["config"]),
        request.get("tamper", False),
    )
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
    sys.exit(1)
