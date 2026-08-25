"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
AGENT_ID = "governed-support-agent"
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[A-Za-z]*\.md$", re.IGNORECASE)


def _new_run_id() -> str:
    """Create a per-invocation identifier for policy and audit records."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"run-{timestamp}-{uuid.uuid4().hex[:8]}"


def _args_hash(args: object) -> str:
    payload = json.dumps(
        args,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ledger_path(log_dir: Path | None) -> Path:
    if log_dir is None:
        return DEFAULT_LEDGER_PATH
    return Path(log_dir) / "ledger.jsonl"


def _ticket_id_from_filename(name: str) -> int | None:
    match = _TICKET_FILE_RE.fullmatch(name)
    return int(match.group(1)) if match else None


def _ticket_customer_map() -> dict[int, list[str]]:
    """Build the trusted ticket_id -> customer_id mapping.

    The mapping comes from the private store's structured ``related_tickets``
    field.  It deliberately does not inspect document text or an LLM result.
    """

    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    mapping: dict[int, list[str]] = {}
    for record in customers:
        customer_id = str(record.get("customer_id", ""))
        if not customer_id:
            continue
        for ticket_id in record.get("related_tickets", []):
            try:
                normalized_ticket_id = int(ticket_id)
            except (TypeError, ValueError):
                continue
            mapping.setdefault(normalized_ticket_id, [])
            if customer_id not in mapping[normalized_ticket_id]:
                mapping[normalized_ticket_id].append(customer_id)
    return mapping


def _call_tool(
    *,
    tool_name: str,
    args: object,
    context: policy.PolicyContext,
    run_id: str,
    ledger_path: Path,
    invoke,
):
    """Authorize, audit, and then invoke one real tool.

    Ledger append happens before execution, including for denied calls.  A
    denied call returns ``(False, None)`` and never invokes the supplied
    function.
    """

    allow, reason = policy.check(context)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": _args_hash(args),
        "classification": context.data_classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
        "agent_owner": context.agent_owner,
        "request_purpose": context.request_purpose,
        "delegation_depth": context.delegation_depth,
        "egress_enabled": context.egress_enabled,
    }
    ledger.append(entry, ledger_path)
    if not allow:
        return False, None
    return True, invoke()


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Handle a request using separate untrusted-content and private-data runs.

    Run A can inspect documents but cannot access private records or egress.
    Run B receives only ticket IDs extracted from trusted filenames, resolves
    them through ``related_tickets``, and reads the resulting customers.  Any
    attempted egress is policy-checked as restricted data before the network
    tool can run.
    """

    ledger_path = _ledger_path(log_dir)
    run_id = _new_run_id()
    run_a_owner = f"{AGENT_ID}/{run_id}/run-a"
    run_b_owner = f"{AGENT_ID}/{run_id}/run-b"

    # ------------------------------ Run A ------------------------------
    # search_docs is the only trifecta tool Run A may execute.  Redaction keeps
    # detected PII out of the LLM context while preserving ticket IDs and the
    # injection markers needed for the containment exercise.
    search_context = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner=run_a_owner,
        delegation_depth=0,
        egress_enabled=False,
    )
    _, docs_result = _call_tool(
        tool_name="search_docs",
        args={"query": message},
        context=search_context,
        run_id=run_id,
        ledger_path=ledger_path,
        invoke=lambda: tools.search_docs(message),
    )
    docs = docs_result or []
    sanitized_docs = [
        {"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs
    ]
    combined_text = "\n\n".join(doc["text"] for doc in sanitized_docs)
    injected = llm.find_injection(combined_text) if combined_text else None

    # Only typed IDs derived from filenames cross the run boundary.  The
    # customer_ids returned by find_injection() are intentionally ignored.
    ticket_ids = sorted(
        {
            ticket_id
            for doc in docs
            if (ticket_id := _ticket_id_from_filename(str(doc.get("id", ""))))
            is not None
        }
    )

    # ------------------------------ Run B ------------------------------
    # Resolve IDs using the structured private-store relation, never attacker
    # free text.  A customer is read at most once even if several tickets map
    # to that customer.
    ticket_to_customers = _ticket_customer_map()
    records: list[dict] = []
    read_customer_context = policy.PolicyContext(
        data_classification="restricted",
        request_purpose="reconciliation-read",
        agent_owner=run_b_owner,
        delegation_depth=1,
        egress_enabled=False,
    )
    seen_customer_ids: set[str] = set()
    for ticket_id in ticket_ids:
        for customer_id in ticket_to_customers.get(ticket_id, []):
            if customer_id in seen_customer_ids:
                continue
            seen_customer_ids.add(customer_id)
            allowed, record = _call_tool(
                tool_name="read_customer",
                args={"customer_id": customer_id},
                context=read_customer_context,
                run_id=run_id,
                ledger_path=ledger_path,
                invoke=lambda customer_id=customer_id: tools.read_customer(customer_id),
            )
            if allowed and record is not None:
                records.append(record)

    # An injection is evidence of an attempted egress, even when its
    # customer_ids are untrusted or there are no matching records.  The body
    # contains only records obtained through the trusted mapping above.
    if injected is not None:
        target_url = getattr(injected, "target_url", "http://localhost:9999/reconcile")
        egress_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation-egress",
            agent_owner=run_b_owner,
            delegation_depth=1,
            egress_enabled=True,
        )
        _call_tool(
            tool_name="http_post",
            args={"url": target_url, "body": {"records": records}},
            context=egress_context,
            run_id=run_id,
            ledger_path=ledger_path,
            invoke=lambda: tools.http_post(target_url, {"records": records}),
        )

    return llm.summarize(sanitized_docs)
