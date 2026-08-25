"""Local exfil sink — mô phỏng đích mà attacker muốn agent POST dữ liệu tới.

Chỉ nghe trên localhost:9999. Mọi request POST được ghi 1 dòng JSON vào
reports/sink.log: {"path": ..., "body": ...}. Không có gì trong file này
cần sinh viên sửa.

Dùng ở tab riêng trong lúc học:
    python sink/sink.py            # chạy server
    python sink/sink.py --reset    # xoá log, dùng trước khi replay/prove
"""
from __future__ import annotations

import argparse
import json
import threading
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

class _FastHTTPServer(HTTPServer):
    """HTTPServer mà KHÔNG gọi socket.getfqdn() khi bind.

    Trên macOS, HTTPServer.server_bind() gọi getfqdn() để đặt server_name,
    kích hoạt một lần reverse-DNS lookup có thể treo ~35s (tuỳ cấu hình
    DNS). Với một sink chỉ nghe localhost, server_name không cần thiết, nên
    ta bind thẳng qua TCPServer và tự đặt tên — startup tức thì.
    """

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
LOG_PATH = REPORTS_DIR / "sink.log"


def make_handler(log_path: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 (http.server naming convention)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            entry = {"path": self.path, "body": body.decode("utf-8", "replace")}
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, fmt, *args):  # im lặng, khỏi làm ồn terminal
            pass

    return Handler


def create_server(port: int = 9999, log_path: Path | None = None) -> HTTPServer:
    log_path = log_path or LOG_PATH
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return _FastHTTPServer(("localhost", port), make_handler(log_path))


def reset_log(log_path: Path | None = None) -> None:
    log_path = log_path or LOG_PATH
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")


def run_in_background(port: int = 9999, log_path: Path | None = None) -> tuple[HTTPServer, threading.Thread]:
    """Dùng trong tests/conftest.py để không cần mở tab riêng khi chấm điểm."""
    server = create_server(port=port, log_path=log_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main() -> None:
    parser = argparse.ArgumentParser(description="Local exfil sink cho Lab 24")
    parser.add_argument("--reset", action="store_true", help="Xoá reports/sink.log rồi thoát")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()

    if args.reset:
        reset_log()
        print(f"đã reset {LOG_PATH}")
        return

    server = create_server(port=args.port)
    print(f"sink đang nghe tại http://localhost:{args.port}, log vào {LOG_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
