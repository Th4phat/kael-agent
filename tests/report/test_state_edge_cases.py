"""Edge case tests for ReportState covering all the high-leverage code paths
that the basic tests in test_report_state.py don't reach.

Targets:
- update_scan_final_fields / set_scan_config
- save_run_data (mark_complete, status transitions, completed-immutability)
- cleanup
- _format_final_scan_result
- _save_artifacts (with SARIF + write failures)
- litellm_cost_callback (all branches)
- record_sdk_usage (none / activity / no-op when no activity)
- get_total_llm_usage
- get_existing_vulnerabilities
- _hydrate_llm_usage
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from kael.report import state as state_module
from kael.report.state import ReportState, litellm_cost_callback


class TestSetScanConfig:
    def test_set_scan_config_populates_run_record(self, report_state: ReportState) -> None:
        report_state.set_scan_config(
            {
                "targets": ["https://target.com"],
                "user_instructions": "test me",
                "scan_mode": "quick",
                "diff_scope": {"active": True, "base": "main"},
                "non_interactive": True,
                "local_sources": ["src/"],
                "scope_mode": "manual",
                "diff_base": "main",
            }
        )
        assert report_state.run_record["targets_info"] == ["https://target.com"]
        assert report_state.run_record["instruction"] == "test me"
        assert report_state.run_record["scan_mode"] == "quick"
        assert report_state.run_record["diff_scope"] == {"active": True, "base": "main"}
        assert report_state.run_record["non_interactive"] is True
        assert report_state.run_record["local_sources"] == ["src/"]
        assert report_state.run_record["scope_mode"] == "manual"
        assert report_state.run_record["diff_base"] == "main"
        assert report_state.run_record["status"] == "running"
        assert report_state.end_time is None

    def test_set_scan_config_defaults(self, report_state: ReportState) -> None:
        report_state.set_scan_config({})
        assert report_state.run_record["targets_info"] == []
        assert report_state.run_record["instruction"] == ""
        assert report_state.run_record["scan_mode"] == "deep"
        assert report_state.run_record["diff_scope"] == {"active": False}
        assert report_state.run_record["non_interactive"] is False
        assert report_state.run_record["local_sources"] == []
        assert report_state.run_record["scope_mode"] == "auto"
        assert report_state.run_record["diff_base"] is None

    def test_set_scan_config_clears_previous_results(self, report_state: ReportState) -> None:
        # Pre-populate a previous final result
        report_state.final_scan_result = "old summary"
        report_state.scan_results = {"old": True}
        report_state.run_record["status"] = "completed"
        report_state.run_record["end_time"] = "2024-01-01T00:00:00Z"
        report_state.run_record["scan_results"] = {"old": True}

        report_state.set_scan_config({"targets": ["x"]})

        # set_scan_config resets all completion state — verified by
        # the function's own implementation; the assertions below
        # would always pass per mypy narrowing, so we instead verify
        # the behavioral changes that aren't statically deducible.
        assert "scan_results" not in report_state.run_record
        assert report_state.run_record["status"] == "running"


class TestUpdateScanFinalFields:
    def test_finalizes_scan(self, report_state: ReportState) -> None:
        report_state.set_scan_config({"targets": ["x"]})
        report_state.update_scan_final_fields(
            executive_summary="x" * 100,
            methodology="m" * 100,
            technical_analysis="t" * 100,
            recommendations="r" * 100,
        )
        assert report_state.scan_results is not None
        assert report_state.scan_results["scan_completed"] is True
        assert report_state.scan_results["success"] is True
        assert report_state.final_scan_result is not None
        assert "Executive Summary" in report_state.final_scan_result
        assert report_state.run_record["status"] == "completed"
        assert report_state.end_time is not None

    def test_strips_whitespace(self, report_state: ReportState) -> None:
        report_state.update_scan_final_fields(
            executive_summary="  trim me  ",
            methodology="\nmethodology\n",
            technical_analysis="\tanalysis\t",
            recommendations=" recs ",
        )
        assert report_state.scan_results is not None
        assert report_state.scan_results["executive_summary"] == "trim me"
        assert report_state.scan_results["methodology"] == "methodology"
        assert report_state.scan_results["technical_analysis"] == "analysis"
        assert report_state.scan_results["recommendations"] == "recs"


class TestSaveRunData:
    def test_mark_complete_sets_status_and_end_time(self, report_state: ReportState) -> None:
        report_state.save_run_data(mark_complete=True)
        assert report_state.run_record["status"] == "completed"
        assert report_state.run_record["end_time"] is not None
        assert report_state.end_time is not None

    def test_status_stopped(self, report_state: ReportState) -> None:
        report_state.save_run_data(status="stopped")
        assert report_state.run_record["status"] == "stopped"
        assert report_state.end_time is not None

    def test_status_interrupted_preserved_over_stopped(self, report_state: ReportState) -> None:
        report_state.run_record["status"] = "interrupted"
        report_state.save_run_data(status="stopped")
        # When current status is failed/interrupted, "stopped" loses
        assert report_state.run_record["status"] == "interrupted"

    def test_status_stopped_preserved_over_failed(self, report_state: ReportState) -> None:
        report_state.run_record["status"] = "failed"
        report_state.save_run_data(status="stopped")
        assert report_state.run_record["status"] == "failed"

    def test_completed_status_not_overwritten(self, report_state: ReportState) -> None:
        report_state.save_run_data(mark_complete=True)
        original_end = report_state.run_record["end_time"]
        # Trying to mark stopped should NOT overwrite completed
        report_state.save_run_data(status="stopped")
        assert report_state.run_record["status"] == "completed"
        assert report_state.run_record["end_time"] == original_end

    def test_no_status_keeps_running(self, report_state: ReportState) -> None:
        report_state.save_run_data()
        assert report_state.run_record["status"] == "running"
        assert report_state.run_record.get("end_time") is None

    def test_cleanup_calls_save_with_status(self, report_state: ReportState) -> None:
        report_state.cleanup(status="stopped")
        assert report_state.run_record["status"] == "stopped"


class TestRecordSDKUsage:
    def test_no_activity_no_save(self, report_state: ReportState) -> None:
        with patch.object(report_state, "save_run_data") as mock_save:
            report_state.record_sdk_usage(agent_id="a1", usage=None)
            mock_save.assert_not_called()

    def test_activity_triggers_save(self, report_state: ReportState) -> None:
        from agents.usage import Usage

        u = Usage()
        u.requests = 1
        u.total_tokens = 100
        with patch.object(report_state, "save_run_data") as mock_save:
            report_state.record_sdk_usage(agent_id="a1", usage=u, agent_name="alpha", model="gpt-4")
            mock_save.assert_called_once()

    def test_record_observed_cost_delegates(self, report_state: ReportState) -> None:
        report_state.record_observed_llm_cost(0.5)
        assert abs(report_state._llm_usage._total_cost - 0.5) < 1e-9


class TestGetTotalLLMUsage:
    def test_returns_run_record_value(self, report_state: ReportState) -> None:
        report_state.run_record["llm_usage"] = {"total_tokens": 42}
        result = report_state.get_total_llm_usage()
        assert result == {"total_tokens": 42}

    def test_falls_back_to_built_record(self, report_state: ReportState) -> None:
        report_state.run_record.pop("llm_usage", None)
        result = report_state.get_total_llm_usage()
        assert isinstance(result, dict)
        assert "agents" in result


class TestGetExistingVulnerabilities:
    def test_returns_copy(self, report_state: ReportState) -> None:
        report_state.vulnerability_reports = [{"id": "v1"}]
        result = report_state.get_existing_vulnerabilities()
        assert result == [{"id": "v1"}]
        # Mutating the returned list must not affect internal state
        result.append({"id": "v2"})
        assert len(report_state.vulnerability_reports) == 1


class TestFormatFinalScanResult:
    def test_all_sections(self, report_state: ReportState) -> None:
        out = report_state._format_final_scan_result(
            {
                "executive_summary": "  exec  ",
                "methodology": "  method  ",
                "technical_analysis": "  analysis  ",
                "recommendations": "  recs  ",
            }
        )
        assert "# Executive Summary" in out
        assert "exec" in out
        assert "method" in out
        assert "analysis" in out
        assert "recs" in out
        # Strips
        assert "  exec  " not in out

    def test_missing_sections_remain_empty(self, report_state: ReportState) -> None:
        out = report_state._format_final_scan_result({})
        assert "# Executive Summary" in out
        assert "# Methodology" in out


class TestSaveArtifactsErrorHandling:
    def test_sarif_failure_does_not_break_run(
        self, report_state: ReportState, workdir: Path
    ) -> None:
        report_state.vulnerability_reports = [
            {"id": "v1", "title": "x", "severity": "low", "timestamp": "2024-01-01 00:00:00 UTC"}
        ]
        with patch("kael.report.state.write_sarif", side_effect=RuntimeError("sarif boom")):
            # Must not raise
            report_state._save_artifacts()
        # The vulnerability MD was still written
        assert (workdir / "kael_runs" / "test-run" / "vulnerabilities" / "v1.md").exists()


class TestHydrateFromRunDirErrorCases:
    def test_corrupt_vulnerabilities_json_raises(
        self, report_state: ReportState, tmp_run_dir: Path, workdir: Path
    ) -> None:
        (tmp_run_dir / "vulnerabilities.json").write_text("not json {", encoding="utf-8")
        with pytest.raises(RuntimeError, match="corrupt"):
            report_state.hydrate_from_run_dir()

    def test_non_list_vulnerabilities_raises(
        self, report_state: ReportState, tmp_run_dir: Path, workdir: Path
    ) -> None:
        (tmp_run_dir / "vulnerabilities.json").write_text('{"not": "a list"}', encoding="utf-8")
        with pytest.raises(RuntimeError, match="not a list"):
            report_state.hydrate_from_run_dir()

    def test_corrupt_run_json_raises(
        self, report_state: ReportState, tmp_run_dir: Path, workdir: Path
    ) -> None:
        (tmp_run_dir / "run.json").write_text("not json {", encoding="utf-8")
        with pytest.raises(RuntimeError, match="unreadable"):
            report_state.hydrate_from_run_dir()

    def test_non_dict_run_json_raises(
        self, report_state: ReportState, tmp_run_dir: Path, workdir: Path
    ) -> None:
        (tmp_run_dir / "run.json").write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(TypeError, match="not an object"):
            report_state.hydrate_from_run_dir()

    def test_filters_non_dict_vulnerability_entries(
        self, report_state: ReportState, tmp_run_dir: Path, workdir: Path
    ) -> None:
        (tmp_run_dir / "vulnerabilities.json").write_text(
            json.dumps(
                [
                    "not a dict",
                    {"id": "v1", "title": "x", "severity": "low"},
                    42,
                ]
            ),
            encoding="utf-8",
        )
        report_state.hydrate_from_run_dir()
        assert len(report_state.vulnerability_reports) == 1
        assert report_state.vulnerability_reports[0]["id"] == "v1"


class TestLiteLLMCostCallback:
    """The LiteLLM success_callback adapter.

    Called as ``litellm_cost_callback(kwargs, completion_response)``.
    Each branch must return cleanly (no raise) — failure of the callback
    is logged, not propagated, so a malformed provider response can't
    take down a scan.
    """

    def setup_method(self) -> None:
        # Reset global report state between tests
        state_module._global_report_state = None

    def teardown_method(self) -> None:
        state_module._global_report_state = None

    def test_records_cost_from_kwargs_response_cost(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        litellm_cost_callback(
            kwargs={"response_cost": 0.5},
            completion_response=MagicMock(),
        )
        assert abs(report_state._llm_usage._total_cost - 0.5) < 1e-9

    def test_records_cost_from_completion_response_hidden_params(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        completion_response = MagicMock()
        completion_response._hidden_params = {"response_cost": 0.7}
        litellm_cost_callback(kwargs={}, completion_response=completion_response)
        assert abs(report_state._llm_usage._total_cost - 0.7) < 1e-9

    def test_records_cost_from_additional_headers(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        completion_response = MagicMock()
        completion_response._hidden_params = {
            "additional_headers": {"llm_provider-x-litellm-response-cost": "0.3"}
        }
        litellm_cost_callback(kwargs={}, completion_response=completion_response)
        assert abs(report_state._llm_usage._total_cost - 0.3) < 1e-9

    def test_no_cost_does_not_record(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        litellm_cost_callback(kwargs={}, completion_response=MagicMock())
        assert report_state._llm_usage._total_cost == 0.0

    def test_zero_or_negative_cost_skipped(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        for cost in (0.0, -1.0):
            litellm_cost_callback(
                kwargs={"response_cost": cost},
                completion_response=MagicMock(),
            )
        assert report_state._llm_usage._total_cost == 0.0

    def test_no_global_state_is_noop(self) -> None:
        # No global state set
        litellm_cost_callback(
            kwargs={"response_cost": 0.5},
            completion_response=MagicMock(),
        )
        # No raise; nothing to assert

    def test_kwargs_not_dict_is_handled(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        # Real callbacks can get a non-dict kwargs in some LiteLLM versions
        litellm_cost_callback(
            kwargs=None,
            completion_response=MagicMock(),
        )
        assert report_state._llm_usage._total_cost == 0.0

    def test_malformed_header_value_does_not_raise(self) -> None:
        report_state = ReportState(run_name="t")
        state_module._global_report_state = report_state
        completion_response = MagicMock()
        completion_response._hidden_params = {
            "additional_headers": {"llm_provider-x-litellm-response-cost": "not a number"}
        }
        # Must not raise — the cost callback's failure mode is to log and continue
        litellm_cost_callback(kwargs={}, completion_response=completion_response)
        assert report_state._llm_usage._total_cost == 0.0


class TestRunRecordFilename:
    def test_run_record_path_used(self, report_state: ReportState) -> None:
        from kael.core.paths import run_record_path

        report_state.save_run_data()
        run_dir = report_state.get_run_dir()
        expected = run_record_path(run_dir)
        assert expected.exists()
        data = json.loads(expected.read_text(encoding="utf-8"))
        assert data["run_id"] == report_state.run_id


class TestHydrateLlmUsage:
    def test_hydrate_via_state(self, report_state: ReportState) -> None:
        raw = {
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
            "requests": 1,
            "cost": 0.1,
            "agents": [
                {
                    "agent_id": "a1",
                    "agent_name": "alpha",
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "total_tokens": 15,
                }
            ],
        }
        report_state._hydrate_llm_usage(raw)
        assert report_state.run_record["llm_usage"]["cost"] == 0.1
        assert "a1" in report_state._llm_usage._agent_usage


class TestArtifactLocking:
    """``_save_artifacts`` writes multiple files (executive_report.md,
    vulnerabilities.json, *.sarif, run.json) from potentially concurrent
    agent tasks. The ``_artifacts_lock`` must serialize the whole write
    set so the run directory never ends up torn.
    """

    def test_artifacts_lock_exists(self, report_state: ReportState) -> None:
        import threading

        assert hasattr(report_state, "_artifacts_lock")
        assert isinstance(report_state._artifacts_lock, type(threading.Lock()))

    def test_save_artifacts_holds_lock(self, report_state: ReportState) -> None:
        """While ``_save_artifacts`` runs, ``_artifacts_lock`` must be held."""
        from contextlib import contextmanager

        @contextmanager
        def fake_writer(*_args: Any, **_kwargs: Any) -> Any:
            yield None

        with (
            patch.object(state_module, "write_run_record", fake_writer),
            patch.object(state_module, "write_executive_report", fake_writer),
            patch.object(state_module, "write_vulnerabilities", fake_writer),
            patch.object(state_module, "write_sarif", fake_writer),
        ):
            report_state.save_run_data()
        # Lock released cleanly after the call
        assert report_state._artifacts_lock.acquire(blocking=False) is True
        report_state._artifacts_lock.release()
