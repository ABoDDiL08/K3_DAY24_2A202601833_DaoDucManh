# Compliance mapping

Phạm vi của bảng này là bản mapping cho bài lab, không phải kết luận tư vấn pháp lý. Evidence trỏ tới mã nguồn, log và lịch sử git đang có trong repository.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | **Chưa implement, xem stretch #4**. Ledger hiện là append-only và chưa có delete cascade cho một chủ thể dữ liệu. | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory trong DPIA; nhận diện rõ nhánh `--model` có thể gửi context tới model provider, đồng thời redact PII trước khi context được đưa vào LLM. Việc lập hồ sơ/đánh giá chu kỳ 60 ngày vẫn là trách nhiệm vận hành, chưa được tự động hoá trong code. | [`reports/dpia-lite.md`](dpia-lite.md) §2–3; [`agent/runner.py`](../agent/runner.py):196–200; [`agent/llm.py`](../agent/llm.py):119–133 |
| ASI03 — privilege abuse | Mỗi invocation có `agent_id`, `run_id`, owner theo run, `delegation_depth` và timestamp trong ledger. Vòng đời run giới hạn phạm vi định danh; **chưa có TTL/timeout độc lập**. | [`agent/runner.py`](../agent/runner.py):67–75, 140–153; [`agent/policy.py`](../agent/policy.py):30–36; [`reports/ledger.jsonl`](ledger.jsonl):46 |
| ASI01 — goal hijack | Trifecta split: Run A chỉ đọc nội dung không tin cậy; Run B chỉ nhận ticket ID kiểu số từ tên file rồi tra `related_tickets`; `http_post` bị policy deny trước khi execute. | [`agent/runner.py`](../agent/runner.py):161–262; [`tests/test_split.py`](../tests/test_split.py):75–115; [`reports/attack-after.log`](attack-after.log) (0 byte) |
| ISO 42001 Clause 5–6 | Policy-as-code có rule tối thiểu `restricted + egress_enabled -> deny`, mọi nhánh trả về reason không rỗng và thay đổi được lưu qua checkpoint/review trong git. | [`agent/policy.py`](../agent/policy.py):39–75; `git log --oneline -- agent/policy.py` → `9413060 Checkpoint 3b` |
