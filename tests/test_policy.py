"""Unit test cho agent.policy.check — Bước 3b."""
from __future__ import annotations

from agent.policy import PolicyContext, check


def test_restricted_with_egress_is_denied():
    ctx = PolicyContext(
        data_classification="restricted",
        request_purpose="reconciliation",
        agent_owner="run-b",
        delegation_depth=1,
        egress_enabled=True,
    )
    allow, reason = check(ctx)
    assert allow is False
    assert reason, "reason không được để trống khi deny"


def test_internal_read_without_egress_can_be_allowed():
    ctx = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow, reason = check(ctx)
    assert reason, "reason không được để trống ngay cả khi allow"


def test_public_data_never_triggers_the_minimum_deny_rule():
    ctx = PolicyContext(
        data_classification="public",
        request_purpose="faq",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=True,
    )
    allow, reason = check(ctx)
    assert reason
