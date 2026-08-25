"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_REQUIRED_FIELDS = {
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
}
_GENESIS_HASH = "0" * 64


def _canonical_payload(entry: dict) -> str:
    """Serialize an entry deterministically, excluding its stored hash."""

    payload = dict(entry)
    payload.pop("hash", None)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical_payload(entry).encode("utf-8")).hexdigest()


def _validate_entry_shape(entry: dict) -> bool:
    if not isinstance(entry, dict):
        return False
    if not _REQUIRED_FIELDS.issubset(entry):
        return False
    reason = entry.get("reason")
    return isinstance(reason, str) and bool(reason.strip())


def append(entry: dict, path: Path) -> dict:
    """Append one audited tool decision to a tamper-evident JSONL ledger."""

    if not isinstance(entry, dict):
        raise TypeError("ledger entry must be a dict")
    missing = sorted(_REQUIRED_FIELDS.difference(entry))
    if missing:
        raise ValueError(f"ledger entry thiếu field: {', '.join(missing)}")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = _GENESIS_HASH
    if path.exists() and path.stat().st_size:
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines or not lines[-1].strip():
            raise ValueError("ledger hiện tại có dòng trống hoặc không hợp lệ")
        try:
            previous_entry = json.loads(lines[-1])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("ledger hiện tại có JSON không hợp lệ") from exc
        previous_hash = previous_entry.get("hash")
        if not isinstance(previous_hash, str) or len(previous_hash) != 64:
            raise ValueError("ledger hiện tại thiếu hash hợp lệ ở dòng cuối")

    record = dict(entry)
    # Caller-supplied chain fields must never be trusted or reused.
    record.pop("hash", None)
    record["prev_hash"] = previous_hash
    record["hash"] = _entry_hash(record)

    with path.open("a", encoding="utf-8", newline="") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
        stream.write("\n")
    return record


def verify(path: Path) -> bool:
    """Verify every record and link in a JSONL hash chain."""

    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return True

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False

    previous_hash = _GENESIS_HASH
    for line in lines:
        if not line.strip():
            return False
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return False
        if not isinstance(record, dict) or not _validate_entry_shape(record):
            return False

        stored_previous = record.get("prev_hash")
        stored_hash = record.get("hash")
        if stored_previous != previous_hash:
            return False
        if not isinstance(stored_hash, str) or len(stored_hash) != 64:
            return False
        if _entry_hash(record) != stored_hash:
            return False
        previous_hash = stored_hash

    return True
