"""Ba tool cố tình dựng thành đúng 3 chân của lethal trifecta.

    search_docs    -> chân 1: untrusted content (đọc corpus/, nơi attacker
                      cài payload)
    read_customer  -> chân 2: private data (đọc data/customers.json)
    http_post      -> chân 3: exfil vector (chỉ trỏ được vào localhost:9999)

KHÔNG thêm chân thứ 4 (một tool mới đọc + viết + gọi network cùng lúc sẽ
tái tạo lại đúng vấn đề mà cả bài lab đang giải quyết). Sinh viên không cần
sửa file này.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
CORPUS_DIR = BASE_DIR / "corpus"
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"

# Allowlist cứng: lab chỉ được phép "tấn công" chính nó, không bao giờ ra
# Internet thật. Đừng nới allowlist này ra cho vui.
ALLOWED_EGRESS_HOST = "localhost"
ALLOWED_EGRESS_PORT = 9999


class ToolError(Exception):
    """Lỗi khi gọi tool: customer không tồn tại, URL bị chặn, v.v."""


def search_docs(query: str, corpus_dir: Path | None = None) -> list[dict]:
    """Chân 1: untrusted content.

    Tìm kiếm từ khoá đơn giản trên toàn bộ file .md trong corpus_dir.
    Trả về **toàn văn** nội dung mỗi ticket khớp — đây chính là bề mặt tấn
    công: bất cứ thứ gì nằm trong file .md sẽ đi vào context của agent
    nguyên văn, kể cả một HTML comment giả làm "ghi chú hệ thống".

    Returns: list[{"id": <tên file>, "text": <toàn văn nội dung>}]
    """
    corpus_dir = corpus_dir or CORPUS_DIR
    terms = [t.lower() for t in query.split() if t]
    results = []
    for path in sorted(corpus_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        haystack = text.lower()
        if not terms or any(t in haystack for t in terms):
            results.append({"id": path.name, "text": text})
    return results


def read_customer(customer_id: str, customers_file: Path | None = None) -> dict:
    """Chân 2: private data store.

    customer_id có dạng "KH-000123". Raise ToolError nếu không tìm thấy.
    """
    customers_file = customers_file or CUSTOMERS_FILE
    customers = json.loads(customers_file.read_text(encoding="utf-8"))
    for record in customers:
        if str(record["customer_id"]) == str(customer_id):
            return record
    raise ToolError(f"unknown customer_id: {customer_id}")


def http_post(url: str, body: dict, timeout: float = 5.0) -> dict:
    """Chân 3: exfil vector.

    Hard-allowlist vào http://localhost:9999/*. Đây KHÔNG phải là một
    security control mà sinh viên có thể dựa vào — nó tồn tại để bài lab
    chạy an toàn (không ai vô tình POST PII ra Internet thật), không phải
    để chứng minh containment. Containment thật nằm ở policy.py/runner.py.
    """
    parsed = urlparse(url)
    if parsed.hostname != ALLOWED_EGRESS_HOST or parsed.port != ALLOWED_EGRESS_PORT:
        raise ToolError(
            f"http_post bị chặn cứng: chỉ cho phép "
            f"http://{ALLOWED_EGRESS_HOST}:{ALLOWED_EGRESS_PORT}/*, "
            f"nhận được {url!r}. Không trỏ sink ra Internet."
        )
    resp = requests.post(url, json=body, timeout=timeout)
    return {"status_code": resp.status_code}
