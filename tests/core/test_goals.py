"""Self-checks for host-owned goal state (budget + verification oracle).

The money/security path: a hard cap must actually cap, and a guessed flag
must not verify as success.
"""

from __future__ import annotations

import hashlib

from kael.core.goals import Budget, Criterion, GoalState, goal_from_scan_config


class _NoGoalSettings:
    """Minimal settings stand-in with no configured budget."""

    goal = None


def test_budget_inert_when_unconfigured() -> None:
    b = Budget()
    assert not b.configured()
    # Unlimited: every consume succeeds, never exhausted.
    for _ in range(1000):
        assert b.try_consume_model_call()
    assert not b.exhausted()


def test_model_call_cap_allows_exactly_n() -> None:
    b = Budget(max_model_calls=3)
    assert [b.try_consume_model_call() for _ in range(5)] == [True, True, True, False, False]
    assert b.consumed_model_calls == 3
    assert b.exhausted()


def test_tool_call_cap() -> None:
    b = Budget(max_tool_calls=2)
    assert b.try_consume_tool_call()
    assert b.try_consume_tool_call()
    assert not b.try_consume_tool_call()
    assert b.exhausted()


def test_wall_time_accumulates_across_segments() -> None:
    b = Budget(max_wall_seconds=100.0)
    b.consumed_wall_seconds = 40.0  # restored from a prior segment
    b.start_segment()
    assert b.elapsed_wall() >= 40.0
    b.fold_segment()
    assert b.consumed_wall_seconds >= 40.0
    # Folding twice must not double count the (now closed) segment.
    before = b.consumed_wall_seconds
    b.fold_segment()
    assert b.consumed_wall_seconds == before


def test_ctf_oracle_accepts_only_exact_flag() -> None:
    g = GoalState(criteria=[Criterion(id="flag", kind="ctf_flag", config={"expected_flag": "flag{ok}"})])
    assert g.unmet_ids() == ["flag"]
    # Wrong guess does not pass.
    assert not g.verify("flag", {"flag": "flag{nope}"}).passed
    assert g.unmet_ids() == ["flag"]
    # Correct flag passes and clears the criterion.
    v = g.verify("flag", {"flag": "flag{ok}"})
    assert v.passed and v.available
    assert g.all_met()
    assert g.unmet_ids() == []


def test_ctf_oracle_sha256_mode() -> None:
    digest = hashlib.sha256(b"flag{hashed}").hexdigest()
    g = GoalState(criteria=[Criterion(id="flag", kind="ctf_flag", config={"expected_sha256": digest})])
    assert not g.verify("flag", {"flag": "wrong"}).passed
    assert g.verify("flag", {"flag": "flag{hashed}"}).passed


def test_ctf_candidate_retained_without_oracle() -> None:
    # No expected flag configured: a flag-shaped string is a candidate, not acceptance.
    g = GoalState(criteria=[Criterion(id="flag", kind="ctf_flag", config={})])
    v = g.verify("flag", {"flag": "flag{looks_real}"})
    assert not v.passed
    assert not v.available  # inconclusive, not a failure
    assert g.unmet_ids() == ["flag"]


def test_unknown_criterion_kind_is_unavailable() -> None:
    g = GoalState(criteria=[Criterion(id="x", kind="nonexistent")])
    v = g.verify("x", {})
    assert not v.passed and not v.available


def test_serialization_round_trip_preserves_budget_and_verdicts() -> None:
    g = GoalState(
        objective="demo",
        criteria=[Criterion(id="flag", kind="ctf_flag", config={"expected_flag": "flag{ok}"})],
        budget=Budget(max_model_calls=10, consumed_model_calls=4, consumed_wall_seconds=12.5),
    )
    g.verify("flag", {"flag": "flag{ok}"})
    restored = GoalState.from_dict(g.to_dict())
    assert restored.objective == "demo"
    assert restored.budget.consumed_model_calls == 4
    assert restored.budget.max_model_calls == 10
    assert restored.budget.consumed_wall_seconds == 12.5
    assert restored.all_met()


def test_goal_from_scan_config_builds_ctf_criterion() -> None:
    g = goal_from_scan_config({"expected_flag": "flag{xyz}"}, _NoGoalSettings())
    assert [c.kind for c in g.criteria] == ["ctf_flag"]
    assert not g.budget.configured()
    assert g.verify("flag", {"flag": "flag{xyz}"}).passed


def test_goal_from_scan_config_inert_without_goal() -> None:
    g = goal_from_scan_config({"user_instructions": "do a thing"}, _NoGoalSettings())
    assert g.criteria == []
    assert not g.budget.configured()
    assert g.objective == "do a thing"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("all goal self-checks passed")
