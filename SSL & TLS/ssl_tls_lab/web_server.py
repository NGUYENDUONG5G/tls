"""Local browser interface for the single-message lab."""

from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .message_demo import DemoConfig
from .protocols import run_protocol

ASSETS = Path(__file__).parent / "web"


def make_server(port=0):
    token = secrets.token_hex(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def send(self, status, content_type, body):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            assets = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            }
            if path not in assets:
                self.send(404, "text/plain; charset=utf-8", b"Not found")
                return
            name, content_type = assets[path]
            body = (ASSETS / name).read_bytes()
            if path == "/":
                body = body.replace(
                    b'<script src="/app.js"></script>',
                    f'<script>window.LAB_TOKEN="{token}"</script><script src="/app.js"></script>'.encode(),
                )
            self.send(200, content_type, body)

        def do_POST(self):
            if urlsplit(self.path).path != "/api/message" or not secrets.compare_digest(
                self.headers.get("X-Lab-Token", ""), token
            ):
                self.send(403, "application/json", b'{"error":"Forbidden"}')
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 200_000:
                    raise ValueError("Kích thước yêu cầu không hợp lệ")
                data = json.loads(self.rfile.read(length))
                if not isinstance(data.get("message"), str) or not isinstance(
                    data.get("tamper", False), bool
                ):
                    raise ValueError("Thông điệp hoặc tùy chọn không hợp lệ")
                mode = data.get("mode", "model")
                if mode not in ("model", "real"):
                    raise ValueError("Chế độ không hợp lệ")
                result = run_protocol(
                    data["message"],
                    DemoConfig(**data["config"]),
                    data.get("tamper", False),
                    mode,
                )
                self.send(
                    200,
                    "application/json; charset=utf-8",
                    json.dumps(result, ensure_ascii=False).encode(),
                )
            except (ValueError, TypeError, KeyError, OSError, RuntimeError) as exc:
                self.send(
                    400,
                    "application/json; charset=utf-8",
                    json.dumps({"error": str(exc)}, ensure_ascii=False).encode(),
                )

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main(port=0, open_browser=True):
    server = make_server(port)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Giao diện đang chạy tại {url} (Ctrl+C để dừng)", flush=True)
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
