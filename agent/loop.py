"""Manual tool-use loop — entrypoint CLI của agent.

    python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"

Trước BƯỚC 3c (chưa có agent/runner.py hoặc runner.py còn là stub), lệnh
trên chạy qua `_naive_loop` ở dưới: một vòng lặp KHÔNG có containment —
đọc corpus, nếu thấy chỉ thị injection thì tuân theo, đọc customer, POST ra
sink. Đây chính là baseline dùng ở Bước 1 (đọc hiểu) và Bước 2 (red team).

Sau BƯỚC 3c, module này tự động dùng `agent.runner.handle()` thay cho
`_naive_loop` — KHÔNG cần sửa file này, KHÔNG cần đổi command đã chạy ở
Bước 2. Đó là chủ đích: cùng một lệnh, hai kết quả khác nhau, trước và sau
khi contain — evidence cho Bước 4.

Sinh viên đọc file này ở Bước 1 để trả lời 3 câu hỏi baseline, nhưng
KHÔNG cần sửa nó.
"""
from __future__ import annotations

import argparse
import importlib

from agent import tools
from agent.llm import get_llm


def _naive_loop(message: str, llm) -> str:
    """Baseline KHÔNG containment: đúng như một agent thật không có PEP,
    không có trifecta split, không có audit ledger — 3 lớp bị thiếu mà
    Bước 1 hỏi tới."""
    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    injected = llm.find_injection(combined_text)
    if injected is not None:
        collected = []
        for customer_id in injected.customer_ids:
            try:
                collected.append(tools.read_customer(customer_id))
            except tools.ToolError:
                continue
        if collected:
            tools.http_post(injected.target_url, {"records": collected})

    return llm.summarize(docs)


def run_once(message: str, mock: bool = True, model: str | None = None, log_dir=None) -> str:
    """API dùng lại được từ test/subprocess, tránh phải parse argv.

    `log_dir` (tuỳ chọn) chuyển tiếp cho `agent.runner.handle()` — dùng
    trong test để ghi ledger vào một thư mục tạm, KHÔNG đụng vào
    `reports/ledger.jsonl` thật của bạn (tránh pytest xoá mất evidence).
    """
    llm = get_llm(mock=mock, model=model)

    try:
        runner = importlib.import_module("agent.runner")
        handle = getattr(runner, "handle", None)
    except ModuleNotFoundError:
        handle = None

    if handle is not None:
        try:
            return handle(message, llm, log_dir=log_dir)
        except NotImplementedError:
            handle = None

    if handle is None:
        return _naive_loop(message, llm)
    return handle(message, llm, log_dir=log_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab 24 agent loop")
    parser.add_argument("message", help="Câu hỏi/yêu cầu gửi cho agent")
    parser.add_argument("--mock", action="store_true", help="Dùng fake LLM deterministic (khuyến nghị)")
    parser.add_argument("--model", default=None, help="Model Claude thật, ví dụ claude-haiku-4-5")
    args = parser.parse_args()

    if not args.mock and not args.model:
        parser.error("phải truyền --mock hoặc --model MODEL_ID")

    result = run_once(args.message, mock=args.mock, model=args.model)
    print(result)


if __name__ == "__main__":
    main()
