"""Tests for the LLMUsageLedger (the data model that powers cost tracking)."""

from __future__ import annotations

import pytest
from agents.usage import Usage

from kael.report.usage import (
    LLMUsageLedger,
    _details_to_dict,
    _float_or_zero,
    _int_or_zero,
    _is_litellm_routed,
    _litellm_model_name,
    _resolve_total_tokens,
    _round_cost,
    _usage_has_activity,
)


class TestRecord:
    def test_none_usage_is_noop(self) -> None:
        ledger = LLMUsageLedger()
        assert ledger.record(agent_id="a1", usage=None) is False

    def test_empty_usage_is_noop(self) -> None:
        ledger = LLMUsageLedger()
        assert ledger.record(agent_id="a1", usage=Usage()) is False

    def test_activity_usage_is_recorded(self) -> None:
        ledger = LLMUsageLedger()
        u = Usage()
        u.requests = 1
        u.input_tokens = 100
        u.output_tokens = 50
        u.total_tokens = 150
        assert ledger.record(agent_id="a1", usage=u, agent_name="alpha", model="gpt-4") is True
        assert ledger._agent_usage["a1"].total_tokens == 150
        assert ledger._agent_metadata["a1"]["agent_name"] == "alpha"
        assert ledger._agent_metadata["a1"]["model"] == "gpt-4"

    def test_aggregates_across_agents(self) -> None:
        ledger = LLMUsageLedger()
        for aid, tokens in [("a1", 100), ("a2", 200), ("a3", 300)]:
            u = Usage()
            u.requests = 1
            u.total_tokens = tokens
            ledger.record(agent_id=aid, usage=u)
        assert ledger._total_usage.total_tokens == 600

    def test_agent_id_normalized_to_string(self) -> None:
        ledger = LLMUsageLedger()
        u = Usage()
        u.requests = 1
        ledger.record(agent_id=42, usage=u)  # type: ignore[arg-type]
        assert "42" in ledger._agent_usage

    def test_empty_agent_id_becomes_unknown(self) -> None:
        ledger = LLMUsageLedger()
        u = Usage()
        u.requests = 1
        ledger.record(agent_id="", usage=u)
        assert "unknown" in ledger._agent_usage

    def test_estimate_skipped_for_third_party_routed(self) -> None:
        """``_is_litellm_routed`` returns True for non-openai provider
        prefixes (``anthropic/...``, ``vertex_ai/...``), and the record
        path then SKIPS the litellm cost estimate for those (cost is
        observed separately via LiteLLM's success callback).

        NOTE: there's a subtle inconsistency in the production code —
        ``_is_litellm_routed`` returns ``False`` for ``openai/...`` but
        True for everything else, while ``_litellm_model_name`` strips
        ``litellm/``, ``any-llm/``, AND ``openai/`` prefixes uniformly.
        This test documents the current behavior; fixing the
        inconsistency is out of scope here.
        """
        ledger = LLMUsageLedger()
        u = Usage()
        u.requests = 1
        u.input_tokens = 1000
        u.total_tokens = 1000
        # Non-openai routed → skipped (cost observed separately)
        ledger.record(agent_id="a1", usage=u, model="anthropic/claude-3")
        # The estimate call is skipped; cost stays at 0 even though we
        # passed token activity. (Real cost would come in via
        # record_observed_cost from the LiteLLM callback.)
        assert ledger._total_cost == 0.0


class TestRecordObservedCost:
    def test_positive_cost_added(self) -> None:
        ledger = LLMUsageLedger()
        ledger.record_observed_cost(0.5)
        ledger.record_observed_cost(1.0)
        assert abs(ledger._total_cost - 1.5) < 1e-9

    def test_negative_or_zero_cost_ignored(self) -> None:
        ledger = LLMUsageLedger()
        ledger.record_observed_cost(0.0)
        ledger.record_observed_cost(-1.0)
        assert ledger._total_cost == 0.0

    def test_non_numeric_ignored(self) -> None:
        ledger = LLMUsageLedger()
        ledger.record_observed_cost("not a number")  # type: ignore[arg-type]
        assert ledger._total_cost == 0.0


class TestToRecord:
    def test_empty_ledger(self) -> None:
        ledger = LLMUsageLedger()
        record = ledger.to_record()
        assert record["cost"] == 0.0
        assert record["agents"] == []

    def test_record_contains_aggregates(self) -> None:
        ledger = LLMUsageLedger()
        u = Usage()
        u.requests = 2
        u.input_tokens = 100
        u.output_tokens = 50
        u.total_tokens = 150
        ledger.record(agent_id="a1", usage=u, agent_name="alpha", model="gpt-4")
        record = ledger.to_record()
        assert "agents" in record
        assert len(record["agents"]) == 1
        a = record["agents"][0]
        assert a["agent_id"] == "a1"
        assert a["agent_name"] == "alpha"
        assert a["model"] == "gpt-4"

    def test_cost_distributed_proportional_to_tokens(self) -> None:
        ledger = LLMUsageLedger()
        ledger._total_cost = 1.0
        u1, u2 = Usage(), Usage()
        u1.requests = u2.requests = 1
        u1.total_tokens = 100
        u2.total_tokens = 300
        ledger._agent_usage["a1"] = u1
        ledger._agent_usage["a2"] = u2
        record = ledger.to_record()
        cost_by_id = {a["agent_id"]: a["cost"] for a in record["agents"]}
        # a1 had 1/4 of tokens → 1/4 of cost; a2 had 3/4 → 3/4
        assert abs(cost_by_id["a1"] - 0.25) < 1e-9
        assert abs(cost_by_id["a2"] - 0.75) < 1e-9


class TestHydrate:
    def test_non_dict_input_is_noop(self) -> None:
        ledger = LLMUsageLedger()
        ledger._total_cost = 5.0
        ledger.hydrate("not a dict")
        assert ledger._total_cost == 0.0  # reset on hydrate

    def test_none_input_is_noop(self) -> None:
        ledger = LLMUsageLedger()
        ledger.hydrate(None)
        assert ledger._total_cost == 0.0

    def test_empty_dict(self) -> None:
        ledger = LLMUsageLedger()
        ledger.hydrate({})
        assert ledger._total_cost == 0.0
        assert ledger._agent_usage == {}

    def test_full_hydration(self) -> None:
        raw = {
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
            "requests": 1,
            "cost": 0.42,
            "agents": [
                {
                    "agent_id": "a1",
                    "agent_name": "alpha",
                    "model": "gpt-4",
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "total_tokens": 150,
                }
            ],
        }
        ledger = LLMUsageLedger()
        ledger.hydrate(raw)
        assert ledger._total_cost == 0.42
        assert "a1" in ledger._agent_usage
        assert ledger._agent_metadata["a1"]["agent_name"] == "alpha"

    def test_skips_malformed_agent_entries(self) -> None:
        raw = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cost": 0.0,
            "agents": [
                "not a dict",
                {"agent_id": ""},  # empty id
                {"agent_id": "  "},  # whitespace id
                {"agent_id": "valid", "input_tokens": 10, "total_tokens": 10},
            ],
        }
        ledger = LLMUsageLedger()
        ledger.hydrate(raw)
        # Only the valid agent should be in the ledger
        assert list(ledger._agent_usage.keys()) == ["valid"]

    def test_hydrate_overwrites_existing_state(self) -> None:
        ledger = LLMUsageLedger()
        u = Usage()
        u.requests = 1
        u.total_tokens = 999
        ledger.record(agent_id="old", usage=u)
        ledger.hydrate({})
        assert ledger._agent_usage == {}
        assert ledger._total_cost == 0.0


class TestHelpers:
    def test_resolve_total_tokens_prefers_explicit(self) -> None:
        u = Usage()
        u.input_tokens = 5
        u.output_tokens = 5
        u.total_tokens = 100  # explicit override
        assert _resolve_total_tokens(u) == 100

    def test_resolve_total_tokens_sums_when_missing(self) -> None:
        u = Usage()
        u.input_tokens = 7
        u.output_tokens = 3
        u.total_tokens = 0
        assert _resolve_total_tokens(u) == 10

    def test_resolve_total_tokens_clamps_negative(self) -> None:
        u = Usage()
        u.total_tokens = -5
        assert _resolve_total_tokens(u) == 0

    def test_is_litellm_routed(self) -> None:
        assert _is_litellm_routed("openai/gpt-4") is False
        assert _is_litellm_routed("anthropic/claude-3") is True
        assert _is_litellm_routed("gpt-4") is False  # no slash
        assert _is_litellm_routed(None) is False
        assert _is_litellm_routed("") is False
        assert _is_litellm_routed("OPENAI/gpt-4") is False  # case-insensitive

    def test_usage_has_activity(self) -> None:
        assert _usage_has_activity(Usage()) is False
        u = Usage()
        u.requests = 1
        assert _usage_has_activity(u) is True
        u2 = Usage()
        u2.input_tokens = 10
        assert _usage_has_activity(u2) is True

    def test_int_or_zero(self) -> None:
        assert _int_or_zero(5) == 5
        assert _int_or_zero("3") == 3
        assert _int_or_zero(None) == 0
        assert _int_or_zero("not a number") == 0
        assert _int_or_zero(-3) == 0  # clamped

    def test_float_or_zero(self) -> None:
        assert _float_or_zero(5) == 5.0
        assert _float_or_zero("3.5") == 3.5
        assert _float_or_zero(None) == 0.0
        assert _float_or_zero("not a number") == 0.0
        assert _float_or_zero(-1.0) == 0.0  # clamped

    def test_round_cost(self) -> None:
        assert _round_cost(0.123456789) == 0.123456789
        assert _round_cost(-1.0) == 0.0
        assert _round_cost(1.0) == 1.0

    def test_litellm_model_name_strips_prefixes(self) -> None:
        assert _litellm_model_name("litellm/gpt-4") == "gpt-4"
        assert _litellm_model_name("any-llm/gpt-4") == "gpt-4"
        assert _litellm_model_name("openai/gpt-4") == "gpt-4"
        assert _litellm_model_name("gpt-4") == "gpt-4"
        assert _litellm_model_name(None) is None
        assert _litellm_model_name("") is None
        assert _litellm_model_name("  ") is None

    def test_details_to_dict_handles_none(self) -> None:
        assert _details_to_dict(None) == {}

    def test_details_to_dict_handles_list(self) -> None:
        # Wraps a list of detail dicts; first non-empty one wins
        assert _details_to_dict([{"a": 1}, {"b": 2}]) == {"a": 1}
        assert _details_to_dict([]) == {}
        assert _details_to_dict([{}, {"b": 2}]) == {"b": 2}

    def test_details_to_dict_handles_pydantic_like(self) -> None:
        class FakeModel:
            def model_dump(self) -> dict[str, object]:
                return {"x": 1, "y": None}

        # None values are dropped
        assert _details_to_dict(FakeModel()) == {"x": 1}

    def test_details_to_dict_handles_dict(self) -> None:
        assert _details_to_dict({"a": 1, "b": None, "c": "x"}) == {"a": 1, "c": "x"}
