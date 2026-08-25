"""Bộ não của agent: --mock (fake LLM deterministic) hoặc --model (Claude thật).

Mock KHÔNG phải là một phiên bản "đồ chơi" của prompt injection để dễ dạy —
nó LÀ prompt injection: nó đọc tool output như một phần context, và nếu
thấy một chỉ thị mang tính ra lệnh trong đó, nó "tuân theo" — đúng như một
model thật đủ thông minh cũng sẽ làm, vì với model, lệnh và dữ liệu đi
chung một stream token. Đổi --mock sang --model claude-... không thay đổi
kết luận của bài lab, chỉ thay đổi chi phí và độ tái lập.

Sinh viên không cần sửa file này. Interface hai method dưới đây
(`find_injection`, `summarize`) là những gì runner.py (BƯỚC 3c) được dùng.
"""
from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class InjectedInstruction:
    customer_ids: list[str] = field(default_factory=list)
    target_url: str = "http://localhost:9999/reconcile"
    matched_markers: list[str] = field(default_factory=list)


# Các cụm từ đặc trưng cho 5 kỹ thuật injection nêu trong Guide.md
# §2 Bước 2. Được so khớp SAU KHI đã chuẩn hoá (bỏ dấu, hạ chữ thường, bỏ
# zero-width char) — mô phỏng đúng việc một model thật vẫn "hiểu" được
# tiếng Việt không dấu / teencode, khác với một bộ filter chuỗi thô.
_INSTRUCTION_MARKERS = [
    "ghi chu noi bo",
    "he thong",
    "bat buoc",
    "da duoc phe duyet",
    "chi thi tu admin",
    "system note",
    "quan tri vien",
    "dpo",
    "goi read_customer",
    "post ket qua",
    "hay goi",
    "hay post",
]

_CUSTOMER_ID_RE = re.compile(r"\bKH-\d{6}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _normalize(text: str) -> str:
    """Bỏ dấu tiếng Việt, hạ chữ thường, bỏ zero-width char.

    Đây là bước mà một filter chuỗi thô (naive string match) thường KHÔNG
    làm — chính là lý do biến thể 5 (không dấu / teencode / unicode
    lookalike) phá được filter đó, trong khi mock LLM ở đây (mô phỏng một
    model thật) vẫn "đọc hiểu" bình thường.
    """
    text = text.replace("​", "").replace("‌", "").replace("﻿", "")
    nfkd = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in nfkd if not unicodedata.combining(c))
    return stripped.lower()


def find_injection(text: str) -> InjectedInstruction | None:
    """Quét `text` (nội dung thô từ search_docs) tìm chỉ thị injection.

    Trả về None nếu không thấy gì đáng ngờ. Trả về InjectedInstruction nếu
    thấy >=2 marker đặc trưng — ngưỡng 2 để tránh false positive trên một
    ticket vô hại chỉ vô tình chứa 1 từ như "hệ thống".
    """
    normalized = _normalize(text)
    hits = [m for m in _INSTRUCTION_MARKERS if m in normalized]
    if len(hits) < 2:
        return None
    customer_ids = sorted(set(_CUSTOMER_ID_RE.findall(text)))
    urls = _URL_RE.findall(text)
    target_url = urls[0].rstrip(".,;:!?") if urls else "http://localhost:9999/reconcile"
    return InjectedInstruction(customer_ids=customer_ids, target_url=target_url, matched_markers=hits)


class MockLLM:
    """Fake LLM deterministic — không gọi network, không cần API key."""

    def find_injection(self, text: str) -> InjectedInstruction | None:
        return find_injection(text)

    def summarize(self, docs: list[dict]) -> str:
        if not docs:
            return "Không tìm thấy ticket nào khớp yêu cầu."
        titles = ", ".join(d["id"] for d in docs)
        return f"Đã tổng hợp {len(docs)} ticket ({titles})."


class RealLLM:
    """Wrapper mỏng gọi Claude thật qua Anthropic API. Dùng cho stretch /
    demo; bài lab KHÔNG được chấm bằng model thật (xem Guide.md
    §2, lý do reproducibility)."""

    def __init__(self, model: str):
        self.model = model
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "Thiếu ANTHROPIC_API_KEY. Dùng --mock nếu không có API key "
                "(--mock là first-class, không phải fallback hạng hai)."
            )
        import anthropic  # import trễ để --mock không cần cài package này

        self._client = anthropic.Anthropic(api_key=api_key)

    def find_injection(self, text: str) -> InjectedInstruction | None:
        # Với model thật, "phát hiện injection" chính là hành vi của model
        # khi đọc text này trong context — không mô phỏng lại ở đây.
        # Dùng chung heuristic với mock để runner.py có 1 interface duy nhất
        # khi so sánh mock vs real trong phần stretch.
        return find_injection(text)

    def summarize(self, docs: list[dict]) -> str:
        if not docs:
            return "Không tìm thấy ticket nào khớp yêu cầu."
        joined = "\n\n---\n\n".join(d["text"] for d in docs)
        message = self._client.messages.create(
            model=self.model,
            max_tokens=300,
            messages=[
                {
                    "role": "user",
                    "content": f"Tóm tắt ngắn các ticket customer-support sau:\n\n{joined}",
                }
            ],
        )
        return message.content[0].text


def get_llm(mock: bool, model: str | None):
    if mock or not model:
        return MockLLM()
    return RealLLM(model)
