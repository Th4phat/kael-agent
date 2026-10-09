"""Host-owned goal state: budget, acceptance criteria, verification, outcome.

See ``docs/research/agent-goal-loop-plan.md``. The agent chooses actions;
the host owns acceptance criteria, budget accounting, and the terminal
outcome. A run continues on useful work and completes only on verified
evidence — not on the agent's own say-so.

Everything here is **inert unless configured**. A scan with no configured
budget and no required criteria keeps exactly the pre-goal behaviour: the
coordinator holds a ``GoalState`` whose ``budget.configured()`` is False
and whose ``criteria`` is empty, so every gate is a no-op.

Security note (plan §58): check *configuration* (e.g. the expected flag)
lives only in ``Criterion.config``, which the host fills from the scan
config and keeps in coordinator state — never in a sandbox mount the
actor can write. The actor can submit a candidate; it cannot redefine the
oracle.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal


if TYPE_CHECKING:
    from kael.config.settings import Settings


Outcome = Literal["in_progress", "achieved", "incomplete", "needs_input", "cancelled"]
StopReason = Literal["", "no_progress", "budget_exhausted", "needs_input", "cancelled"]


class GoalBudgetExhausted(Exception):
    """Pre-dispatch gate tripped: the goal-wide budget is spent.

    A *policy* stop, deliberately distinct from a transport/model error.
    ``_run_cycle`` recognises it and parks the agent cleanly with a
    partial result. It must never be retried, nor swallowed by an
    error-as-result wrapper (plan §96).
    """

    def __init__(self, reason: StopReason = "budget_exhausted") -> None:
        self.reason: StopReason = reason
        super().__init__(f"goal budget exhausted: {reason}")


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Budget:
    """Goal-wide hard limits shared by root, children, recovery, and the
    verifier — one accounting owner (plan §84). ``max_turns`` stays a
    separate per-invocation SDK guard.

    ``None`` means unlimited. Counts are mutated under the coordinator
    lock, so check-then-increment is atomic across concurrent agents:
    counting at dispatch time *is* the reservation.
    """

    max_model_calls: int | None = None
    max_tool_calls: int | None = None
    max_wall_seconds: float | None = None
    consumed_model_calls: int = 0
    consumed_tool_calls: int = 0
    # Active wall-time folded in from completed run segments; survives
    # resume. The current in-memory segment is tracked separately and is
    # not serialised (monotonic clocks don't survive a restart).
    consumed_wall_seconds: float = 0.0

    def __post_init__(self) -> None:
        self._segment_start: float | None = None

    def configured(self) -> bool:
        return any(
            limit is not None
            for limit in (self.max_model_calls, self.max_tool_calls, self.max_wall_seconds)
        )

    def start_segment(self) -> None:
        self._segment_start = time.monotonic()

    def fold_segment(self) -> None:
        """Persist the current segment's elapsed time, then close it."""
        if self._segment_start is not None:
            self.consumed_wall_seconds += time.monotonic() - self._segment_start
            self._segment_start = None

    def elapsed_wall(self) -> float:
        extra = (time.monotonic() - self._segment_start) if self._segment_start is not None else 0.0
        return self.consumed_wall_seconds + extra

    def try_consume_model_call(self) -> bool:
        """Count one model call, or return False if that would exceed the cap."""
        if self.max_model_calls is not None and self.consumed_model_calls >= self.max_model_calls:
            return False
        self.consumed_model_calls += 1
        return True

    def try_consume_tool_call(self) -> bool:
        if self.max_tool_calls is not None and self.consumed_tool_calls >= self.max_tool_calls:
            return False
        self.consumed_tool_calls += 1
        return True

    def exhausted(self) -> bool:
        """True when any configured hard limit is reached (watchdog backstop)."""
        if self.max_model_calls is not None and self.consumed_model_calls >= self.max_model_calls:
            return True
        if self.max_tool_calls is not None and self.consumed_tool_calls >= self.max_tool_calls:
            return True
        return self.max_wall_seconds is not None and self.elapsed_wall() >= self.max_wall_seconds

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Budget:
        fields = {f for f in cls.__dataclass_fields__}  # noqa: C416
        return cls(**{k: v for k, v in data.items() if k in fields})


@dataclass
class Criterion:
    """One acceptance item. ``config`` is host-owned check configuration
    (e.g. the expected flag / its sha256) and is never agent-writable."""

    id: str
    description: str = ""
    kind: str = "manual"
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    criterion_id: str
    passed: bool
    available: bool = True  # False = the check could not run (inconclusive, not a failure — plan §74)
    evidence: str = ""
    source: str = ""
    checked_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Verifier registry: kind -> (criterion, submission) -> Verdict. Executable
# checks for objective outcomes; a second model reviewing the same claim
# supplies no new environmental evidence (plan §29), so these are functions.
Verifier = Callable[[Criterion, dict[str, Any]], Verdict]


def _verify_ctf_flag(criterion: Criterion, submission: dict[str, Any]) -> Verdict:
    """Trusted fixture oracle: compare the submitted flag to the host's.

    With no configured oracle, the candidate is *retained but unverified*
    (``available=False``) — a flag-shaped string is not acceptance
    (plan §39).
    """
    candidate = str(submission.get("flag", "")).strip()
    cfg = criterion.config or {}
    expected = cfg.get("expected_flag")
    expected_sha = cfg.get("expected_sha256")
    if not candidate:
        return Verdict(criterion.id, passed=False, evidence="no flag submitted", source="ctf_oracle")
    if expected is not None:
        ok = hmac.compare_digest(candidate, str(expected))
    elif expected_sha is not None:
        digest = hashlib.sha256(candidate.encode("utf-8", "surrogatepass")).hexdigest()
        ok = hmac.compare_digest(digest, str(expected_sha).strip().lower())
    else:
        return Verdict(
            criterion.id,
            passed=False,
            available=False,
            evidence=f"candidate retained, no oracle to confirm it: {candidate[:120]}",
            source="ctf_oracle",
        )
    return Verdict(
        criterion.id,
        passed=ok,
        evidence="flag matched oracle" if ok else "flag did not match oracle",
        source="ctf_oracle",
    )


_VERIFIERS: dict[str, Verifier] = {"ctf_flag": _verify_ctf_flag}


@dataclass
class GoalState:
    objective: str = ""
    revision: int = 1
    criteria: list[Criterion] = field(default_factory=list)
    verdicts: dict[str, Verdict] = field(default_factory=dict)
    budget: Budget = field(default_factory=Budget)
    outcome: Outcome = "in_progress"
    stop_reason: StopReason = ""

    def criterion(self, criterion_id: str) -> Criterion | None:
        return next((c for c in self.criteria if c.id == criterion_id), None)

    def unmet_ids(self) -> list[str]:
        """Required criteria without a passing verdict."""
        return [
            c.id
            for c in self.criteria
            if not (self.verdicts.get(c.id) and self.verdicts[c.id].passed)
        ]

    def all_met(self) -> bool:
        return bool(self.criteria) and not self.unmet_ids()

    def verify(self, criterion_id: str, submission: dict[str, Any]) -> Verdict:
        """Run the host check for one criterion and record the verdict."""
        crit = self.criterion(criterion_id)
        if crit is None:
            verdict = Verdict(
                criterion_id, passed=False, available=False, evidence="unknown criterion"
            )
        else:
            verifier = _VERIFIERS.get(crit.kind)
            if verifier is None:
                verdict = Verdict(
                    criterion_id,
                    passed=False,
                    available=False,
                    evidence=f"no verifier for kind {crit.kind!r}",
                )
            else:
                verdict = verifier(crit, submission)
        self.verdicts[criterion_id] = verdict
        return verdict

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "revision": self.revision,
            "criteria": [asdict(c) for c in self.criteria],
            "verdicts": {k: v.to_dict() for k, v in self.verdicts.items()},
            "budget": self.budget.to_dict(),
            "outcome": self.outcome,
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GoalState:
        return cls(
            objective=data.get("objective", ""),
            revision=int(data.get("revision", 1)),
            criteria=[Criterion(**c) for c in data.get("criteria", [])],
            verdicts={k: Verdict(**v) for k, v in data.get("verdicts", {}).items()},
            budget=Budget.from_dict(data.get("budget", {})),
            outcome=data.get("outcome", "in_progress"),
            stop_reason=data.get("stop_reason", ""),
        )


def goal_from_scan_config(scan_config: dict[str, Any], settings: Settings) -> GoalState:
    """Build the fresh-run goal from host-controlled config.

    Budget comes from settings (env); criteria from an optional
    ``scan_config["goal"]`` block, plus a CTF-flag convenience when an
    expected flag is supplied. With neither, the result is fully inert.
    """
    goal_settings = getattr(settings, "goal", None)
    budget = Budget(
        max_model_calls=getattr(goal_settings, "max_model_calls", None),
        max_tool_calls=getattr(goal_settings, "max_tool_calls", None),
        max_wall_seconds=getattr(goal_settings, "max_wall_seconds", None),
    )
    goal_cfg = scan_config.get("goal") or {}
    objective = str(goal_cfg.get("objective") or scan_config.get("user_instructions") or "").strip()
    state = GoalState(objective=objective, budget=budget)
    for raw in goal_cfg.get("criteria") or []:
        state.criteria.append(
            Criterion(
                id=str(raw["id"]),
                description=str(raw.get("description", "")),
                kind=str(raw.get("kind", "manual")),
                config=dict(raw.get("config") or {}),
            )
        )
    expected_flag = goal_cfg.get("expected_flag") or scan_config.get("expected_flag")
    if expected_flag and not any(c.kind == "ctf_flag" for c in state.criteria):
        state.criteria.append(
            Criterion(
                id="flag",
                description="Capture the challenge flag",
                kind="ctf_flag",
                config={"expected_flag": str(expected_flag)},
            )
        )
    return state
