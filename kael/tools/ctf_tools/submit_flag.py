"""``submit_flag`` — confirm a captured flag against the trusted oracle.

This is the CTF acceptance channel (plan §39). A flag-shaped string is
not a solve: the host compares the candidate to the challenge's
acceptance criterion and records the verdict. ``finish_scan`` only
completes as achieved once a required flag criterion is verified here.
"""

from __future__ import annotations

import json

from agents import RunContextWrapper, function_tool

from kael.core.agents import coordinator_from_context


@function_tool(timeout=30)
async def submit_flag(ctx: RunContextWrapper, flag: str) -> str:
    """Submit a recovered flag to the trusted acceptance oracle.

    Call this the moment you have a candidate flag. The host checks it
    against the challenge's acceptance criterion and tells you whether it
    is confirmed. Do not call ``finish_scan`` as a success until this
    returns ``verified: true`` for the required flag.

    Args:
        flag: The exact flag string you recovered (e.g. ``flag{...}``).
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    goal = coordinator.goal if coordinator is not None else None
    if goal is None or not goal.criteria:
        return json.dumps(
            {
                "success": False,
                "verified": False,
                "error": (
                    "No acceptance criterion is configured for this run, so the flag "
                    "cannot be confirmed by an oracle. Record it in your report with the "
                    "exact reproduction steps and finish normally."
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    criterion = next((c for c in goal.criteria if c.kind == "ctf_flag"), None)
    if criterion is None:
        return json.dumps(
            {
                "success": False,
                "verified": False,
                "error": "This run has no flag-acceptance criterion to check against.",
            },
            ensure_ascii=False,
            default=str,
        )

    verdict = await coordinator.record_goal_verdict(criterion.id, {"flag": flag})
    if verdict is None:
        return json.dumps(
            {"success": False, "verified": False, "error": "Goal state unavailable."},
            ensure_ascii=False,
            default=str,
        )

    if verdict.passed:
        note = "Flag confirmed by the oracle. File your report and call finish_scan."
    elif not verdict.available:
        note = (
            "No oracle is available to confirm this flag, so it is retained as an "
            "unverified candidate. Keep your extraction evidence; the run cannot be "
            "marked a verified success without acceptance."
        )
    else:
        note = "Flag rejected by the oracle. Keep working — this is not the accepted flag."

    return json.dumps(
        {
            "success": True,
            "verified": bool(verdict.passed),
            "available": bool(verdict.available),
            "criterion_id": criterion.id,
            "evidence": verdict.evidence,
            "note": note,
        },
        ensure_ascii=False,
        default=str,
    )
