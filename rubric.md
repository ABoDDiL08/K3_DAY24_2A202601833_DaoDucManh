# Rubric (100 điểm)

Chấm bằng `--mock` + `pytest tests/` — không chấm bằng model thật (để
kết quả reproducible).

| Tiêu chí | Điểm | Cách đo |
|---|---|---|
| Attack thành công ở Bước 2, có log | 15 | `reports/attack-before.log` cho thấy PII của `KH-000999` tới sink |
| `injection-corpus.md`: 5 biến thể, 5 kỹ thuật khác nhau | 15 | có mô tả kỹ thuật + kết quả trước/sau cho từng biến thể |
| Block rate sau contain | 20 | `pytest tests/test_injection.py`: 5/5 pass = 20đ · 4/5 = 14đ · ≤3/5 = 6đ |
| PII detection trên VN test set | 15 | `pytest tests/test_pii.py -s`, đọc recall in ra: >95% = 15đ · 85-95% = 10đ · <85% = 4đ |
| **Audit completeness = 100%** | 15 | mọi dòng trong `reports/ledger.jsonl` có `decision` **và** `reason` non-empty |
| Egress deny có bằng chứng | 10 | `reports/ledger.jsonl` có ≥1 dòng `decision=deny` cho tool `http_post`, không phải chỉ file config |
| Compliance mapping + DPIA-lite | 10 | `reports/compliance-mapping.md` có evidence trỏ tới file/dòng thật, `reports/dpia-lite.md` đủ 3 phần (dữ liệu/mục đích/luồng đi) |

## Điều kiện trượt (bất kể tổng điểm)

- `reports/ledger.jsonl` có bất kỳ dòng nào thiếu `reason`.
- `reports/attack-after.log` (hoặc `pytest tests/test_injection.py`) vẫn
  cho thấy PII của `KH-000999` lộ ra sink.

Hai điều kiện này là toàn bộ luận đề của buổi học: **containment không
có bằng chứng = chưa contain**, và **có bằng chứng nhưng attack sau vẫn
lọt = containment không hoạt động**.

## Cách chấm nhanh (dành cho giảng viên/TA)

```bash
cd lab24-governed-agent   # hoặc thư mục sinh viên nộp
pip install -r requirements.txt
python sink/sink.py --reset
pytest -v
```

- `tests/test_pii.py -s` in ra `precision=... recall=...` → tra bảng.
- `tests/test_policy.py` pass/fail trực tiếp map vào yêu cầu "reason
  non-empty" và rule tối thiểu.
- `tests/test_ledger.py` pass/fail map vào "audit completeness" +
  tamper-evidence.
- `tests/test_injection.py -v` in ra bao nhiêu biến thể PASS/SKIP/FAIL
  trên 5 → map trực tiếp vào băng điểm "Block rate sau contain". SKIP =
  biến thể chưa được viết (0 điểm biến thể đó, không phải lỗi hệ thống).
