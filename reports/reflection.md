# Reflection — baseline và câu hỏi chốt buổi

Các nhận định dưới đây dựa trên code và evidence synthetic trong repository.

## 1. Baseline

1. **Identity:** Chưa có. `_naive_loop()` chỉ nhận message/LLM và gọi thẳng các tool, không tạo `agent_id`, `run_id` hay audit record ([`agent/loop.py`](../agent/loop.py):27–54). Identity chỉ xuất hiện sau containment ([`agent/runner.py`](../agent/runner.py):67–75).

2. **Ai gọi `http_post`?** Instruction do LLM đọc từ `search_docs` trả về `customer_ids`/`target_url`; baseline đọc customer rồi POST ngay, không qua policy ([`agent/loop.py`](../agent/loop.py):34–44).

3. **Biết rò rỉ bằng cách nào?** Chỉ xem sink log. [`reports/attack-before.log`](attack-before.log):1 ghi `KH-000999` cùng CCCD, điện thoại và STK; baseline không có ledger hoặc alert.

## 2. Câu hỏi chốt buổi

1. **Đã bỏ chân nào?** Không xoá tool, nhưng tách trifecta: Run A đọc untrusted content; Run B chỉ nhận ticket ID typed và tra `related_tickets`; restricted data bật egress thì bị deny trước `http_post` ([`agent/runner.py`](../agent/runner.py):161–262). Chuỗi **private data → network egress** bị loại bỏ. Sau containment, [`reports/attack-after.log`](attack-after.log) rỗng và [`reports/ledger.jsonl`](ledger.jsonl):46 ghi deny.

2. **Nếu attacker ghi được `corpus/`:** Redaction PII, typed boundary, policy egress và hash-chain ledger vẫn hoạt động. Nhưng filename ticket vẫn là đầu vào được tin; cần authorization/signed documents hoặc allowlist khi triển khai thật. `KH-000777` không bị đọc trong split test ([`tests/test_split.py`](../tests/test_split.py):75–115).

3. **Mở file nào để chứng minh?** Với run sau containment: mở [`reports/attack-after.log`](attack-after.log), [`reports/ledger.jsonl`](ledger.jsonl):46 và chạy `ledger.verify(...)`. Không thể nói “chưa từng rò rỉ” cho toàn bộ lịch sử, vì [`reports/attack-before.log`](attack-before.log):1 chứng minh baseline đã gửi PII synthetic tới local sink.
