# DPIA-lite — governed support agent

**Phạm vi và trạng thái.** Đây là bản đánh giá tác động rút gọn cho agent trong repository này, dùng toàn bộ dữ liệu synthetic của lab. Mặc định đánh giá với `--mock` (xử lý local, deterministic); nhánh `--model` được ghi nhận riêng vì có thể phát sinh chuyển dữ liệu tới nhà cung cấp model. Tài liệu này là inventory kỹ thuật phục vụ bài lab, không thay thế tư vấn pháp lý.

## 1. Dữ liệu được xử lý

- **Nguồn không tin cậy:** nội dung Markdown trong `corpus/`, gồm ticket và prompt-injection do bài lab tạo.
- **Dữ liệu cá nhân synthetic:** `data/customers.json` chứa `customer_id`, tên, CCCD, số điện thoại, số tài khoản, email và quan hệ `related_tickets`. Đây là dữ liệu **restricted/private** khi được đọc qua `read_customer`.
- **Dữ liệu đầu vào và suy ra:** câu hỏi người dùng, tên file/ticket ID, kết quả phát hiện injection, trạng thái policy và metadata audit (`agent_id`, `run_id`, `tool`, `decision`, `reason`, hash). Ledger chỉ lưu `args_hash`, không lưu nguyên body PII.
- **Dữ liệu kiểm thử/evidence:** `reports/attack-before.log` cố ý lưu lại cuộc tấn công baseline có PII synthetic; `reports/attack-after.log` là snapshot sau containment và hiện rỗng. Các file này phải được coi là restricted nếu thay synthetic data bằng dữ liệu thật.

## 2. Mục đích xử lý và cơ sở kiểm soát

Mục đích là tổng hợp ticket hỗ trợ, phát hiện chỉ thị injection, lấy đúng hồ sơ khách hàng liên quan và tạo audit trail cho mọi quyết định gọi tool. `agent/pii.py` nhận diện/redact email, CCCD, điện thoại và STK trước khi nội dung ticket đi vào context LLM. `agent/runner.py` tách Run A (untrusted documents) khỏi Run B (private records); Run B chỉ nhận ticket ID kiểu số từ tên file và resolve qua `related_tickets`, không tin `customer_id` trong free text. `agent/policy.py` là PEP trước tool call: restricted data cùng egress bật luôn bị deny. `agent/ledger.py` ghi cả allow/deny vào JSONL hash-chain để kiểm tra tamper.

Quyền yêu cầu xoá/delete cascade và TTL/timeout độc lập chưa được triển khai; đây là residual governance gap cần xử lý trước production. Ledger append-only không tự chứng minh việc thực hiện quyền xoá.

## 3. Luồng dữ liệu, nơi đến và chuyển biên giới

1. User gửi query tới `agent.loop`. Run A gọi `search_docs` trên `corpus/`; văn bản được redact rồi mới đưa cho `find_injection`/`summarize`.
2. Từ kết quả search, chỉ **ticket ID đã typed** đi qua biên Run A → Run B. Run B đọc `data/customers.json` cục bộ bằng `read_customer`; nội dung PII không được dùng để quyết định customer nào cần đọc.
3. Nếu injection cố gọi exfil, runner tạo quyết định `http_post` với classification `restricted` và `egress_enabled=True`. Policy ghi `deny` vào ledger trước khi invoke, nên không có request tới sink; `reports/attack-after.log` rỗng, trong khi `reports/ledger.jsonl:46` ghi reason deny. `http_post` cũng có allowlist an toàn chỉ tới `localhost:9999`.
4. Với `--mock`, toàn bộ LLM xử lý local. Với `--model`, `agent/llm.py` gọi Anthropic API và gửi chuỗi ticket đã redact trong `summarize`; đây là điểm có thể là chuyển dữ liệu xuyên biên giới. Inventory cần ghi provider/model, thời điểm, loại dữ liệu, mục đích, `run_id`, quốc gia/endpoint, thỏa thuận xử lý dữ liệu và thời hạn lưu. Theo yêu cầu bài lab về NĐ 356/2025, hồ sơ chuyển dữ liệu phải được theo dõi trong chu kỳ 60 ngày; code hiện mới cung cấp điểm kiểm kê/evidence, chưa tự động thực hiện nghĩa vụ đó.

**Kết luận:** containment đã loại bỏ đường đi `private data → egress` trong replay (5/5 injection pass và split test không đọc `KH-000777`), nhưng các gap nêu trên vẫn cần được đóng trước khi dùng dữ liệu thật hoặc bật model provider bên ngoài.
