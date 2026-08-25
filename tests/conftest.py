"""Fixtures dùng chung cho toàn bộ test suite.

Tự khởi động sink server trong background thread (không cần mở tab riêng
`python sink/sink.py` để chấm điểm bằng pytest được reproducible).
"""
from __future__ import annotations

import socket
import time

import pytest

from sink.sink import create_server, reset_log


def _wait_port(port: int, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("localhost", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"sink không lên trong {timeout}s")


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


@pytest.fixture(scope="session")
def sink_server():
    import threading

    # Nếu sinh viên đã chạy `python sink/sink.py` ở tab riêng (theo README),
    # cổng 9999 đã bận — dùng lại sink đó thay vì bind trùng và ném
    # OSError: Address already in use. Cả hai ghi vào cùng reports/sink.log.
    if _port_open(9999):
        yield None
        return

    server = create_server(port=9999)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_port(9999)
    yield server
    server.shutdown()


@pytest.fixture
def clean_sink(sink_server):
    reset_log()
    yield
    reset_log()


@pytest.fixture
def clean_ledger(tmp_path):
    """Ledger tạm, riêng cho mỗi test — KHÔNG dùng reports/ledger.jsonl thật,
    để chạy pytest không xoá mất evidence audit ledger của bạn ở Bước 4."""
    return tmp_path / "ledger.jsonl"
