"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


# The lab data is Vietnamese, so a small set of explicit recognizers is more
# predictable than a general-purpose English NER engine.  The patterns capture
# only the value itself; labels such as ``CCCD`` and ``STK`` are context used to
# classify an otherwise ambiguous digit sequence, not part of the entity span.
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    # Sentence punctuation such as a final period is allowed after the email;
    # a following word character/hyphen would indicate the match is embedded
    # in a larger token.
    r"(?![\w-])"
)

# Account numbers in the supplied corpus are introduced by STK or "số tài
# khoản".  Requiring that context avoids classifying every 10/12-digit value
# as both a phone/CCCD and a bank account.
_BANK_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"\b(?:stk|số\s+tài\s+khoản|so\s+tai\s+khoan)\b"
    r"[^\d]{0,40}(?P<value>\d{8,16})(?!\d)"
)

# Vietnamese phone numbers: 0 followed by 9 or 10 digits.  A single space or
# hyphen between digits is accepted, while the returned span includes those
# separators so redact() can remove exactly what the user supplied.
_PHONE_RE = re.compile(r"(?<!\w)0(?:[ -]?\d){9,10}(?!\w)")

# CCCD is normally labelled explicitly.  The generic recognizer covers a
# standalone 12-digit value; bank-context spans take precedence below.
_CCCD_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"\b(?:cccd|căn\s+cước\s+công\s+dân|can\s+cuoc\s+cong\s+dan)\b"
    r"[^\d]{0,40}(?P<value>\d{12})(?!\d)"
)
_CCCD_RE = re.compile(r"(?<!\w)\d{12}(?!\w)")


def _entity(entity_type: str, match: re.Match[str], group: str | None = None) -> dict:
    """Build the public entity shape from a regex match."""

    if group is None:
        start, end = match.span()
    else:
        start, end = match.span(group)
    return {"type": entity_type, "start": start, "end": end}


def _overlaps(left: dict, right: dict) -> bool:
    return left["start"] < right["end"] and right["start"] < left["end"]


def _deduplicate_and_resolve(candidates: list[dict]) -> list[dict]:
    """Remove duplicate/overlapping recognitions deterministically.

    Contextual recognizers (bank/CCCD labels) are added before generic digit
    recognizers, so keeping the first overlapping span preserves the more
    informative classification.  This also prevents redact() from applying
    two replacements to one piece of text.
    """

    selected: list[dict] = []
    for candidate in sorted(
        candidates,
        key=lambda item: (item["start"], item["end"] - item["start"]),
    ):
        if any(_overlaps(candidate, existing) for existing in selected):
            continue
        selected.append(candidate)
    return selected


def detect(text: str) -> list[dict]:
    """Return detected Vietnamese PII spans in *text*.

    Offsets are Python string offsets (start inclusive, end exclusive).  The
    returned list is ordered from left to right and contains no overlapping
    entities.
    """

    if not isinstance(text, str) or not text:
        return []

    candidates: list[dict] = []

    # Email is the most specific recognizer and is given precedence over any
    # digits that might appear in its local-part or domain.
    email_entities = [_entity("EMAIL", match) for match in _EMAIL_RE.finditer(text)]
    candidates.extend(email_entities)

    bank_entities = [
        _entity("VN_BANK_ACCOUNT", match, "value")
        for match in _BANK_CONTEXT_RE.finditer(text)
    ]
    candidates.extend(bank_entities)

    # Labelled CCCD values are more reliable than the generic 12-digit rule.
    cccd_context_entities = [
        _entity("VN_CCCD", match, "value")
        for match in _CCCD_CONTEXT_RE.finditer(text)
    ]
    candidates.extend(cccd_context_entities)

    # Generic recognizers are filtered against the high-confidence spans above
    # so an STK value cannot also be returned as a CCCD or phone number.
    protected = email_entities + bank_entities + cccd_context_entities
    for match in _PHONE_RE.finditer(text):
        candidate = _entity("VN_PHONE", match)
        if not any(_overlaps(candidate, existing) for existing in protected):
            candidates.append(candidate)

    for match in _CCCD_RE.finditer(text):
        candidate = _entity("VN_CCCD", match)
        if not any(_overlaps(candidate, existing) for existing in protected):
            candidates.append(candidate)

    return _deduplicate_and_resolve(candidates)


def redact(text: str) -> str:
    """Replace every entity returned by detect() with a typed placeholder."""

    if not isinstance(text, str) or not text:
        return text

    redacted = text
    # Replace from right to left so original offsets remain valid even when
    # placeholders have a different length from the matched value.
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        start, end = entity["start"], entity["end"]
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[:start] + replacement + redacted[end:]
    return redacted
