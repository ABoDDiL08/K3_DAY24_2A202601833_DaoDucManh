"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Evaluate the policy before a tool is allowed to execute.

    The minimum non-negotiable rule for the lab is that restricted data must
    never use an enabled egress channel.  Every branch returns a useful,
    non-empty reason because the runner writes both allow and deny decisions to
    the audit ledger.
    """

    if not isinstance(context, PolicyContext):
        return False, "deny: invalid policy context"

    classification = context.data_classification.strip().lower()
    if classification not in {"public", "internal", "restricted"}:
        return False, f"deny: unknown data classification {context.data_classification!r}"

    if not isinstance(context.delegation_depth, int) or context.delegation_depth < 0:
        return False, "deny: delegation_depth must be a non-negative integer"

    if not isinstance(context.egress_enabled, bool):
        return False, "deny: egress_enabled must be a boolean"

    if classification == "restricted" and context.egress_enabled is True:
        return (
            False,
            "deny: restricted data cannot use an enabled egress channel",
        )

    owner = context.agent_owner.strip() or "<unidentified>"
    purpose = context.request_purpose.strip() or "<unspecified>"
    return (
        True,
        "allow: "
        f"classification={classification}, purpose={purpose}, "
        f"agent_owner={owner}, delegation_depth={context.delegation_depth}, "
        f"egress_enabled={context.egress_enabled}",
    )
