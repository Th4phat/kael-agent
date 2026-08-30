"""Tests for ``kael.core.paths`` session path helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from kael.core.paths import (
    FOLDER_SENTINEL,
    InvalidSessionPathError,
    is_folder_dir,
    is_run_dir,
    run_dir_for,
    runs_root,
    validate_session_path,
)


class TestValidateSessionPath:
    @pytest.mark.parametrize(
        "name",
        [
            "simple",
            "with-dash",
            "with_underscore",
            "with.dot",
            "nested/folder/run",
            "deep/nested/folder/run_xx",
            "UPPER_and_lower-123",
        ],
    )
    def test_accepts_valid_names(self, name: str) -> None:
        assert validate_session_path(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            " ",
            " leading",
            "trailing ",
            "/leading-slash",
            "trailing-slash/",
            "double//slash",
            "has\\backslash",
            "~/home",
            "..",
            "../escape",
            "foo/..",
            "foo/../bar",
            ".hidden",
            ".kael_folder",
            "has spaces",
            "has\ttab",
            "has\nnewline",
        ],
    )
    def test_rejects_invalid_names(self, name: str) -> None:
        with pytest.raises(InvalidSessionPathError):
            validate_session_path(name)

    def test_rejects_dot_segment_alone(self) -> None:
        with pytest.raises(InvalidSessionPathError):
            validate_session_path(".")

    def test_returns_same_string_on_success(self) -> None:
        assert validate_session_path("acme/api_xx") is None or (
            validate_session_path("acme/api_xx") == "acme/api_xx"
        )


class TestRunDirFor:
    def test_simple_name(self, tmp_path: Path) -> None:
        assert run_dir_for("foo", cwd=tmp_path) == tmp_path / "kael_runs" / "foo"

    def test_nested_name_creates_nested_path(self, tmp_path: Path) -> None:
        assert run_dir_for("acme/api", cwd=tmp_path) == tmp_path / "kael_runs" / "acme" / "api"

    def test_nested_name_does_not_create_dirs(self, tmp_path: Path) -> None:
        run_dir_for("acme/api", cwd=tmp_path)
        assert not (tmp_path / "kael_runs").exists()


class TestRunsRoot:
    def test_returns_under_cwd(self, tmp_path: Path) -> None:
        assert runs_root(cwd=tmp_path) == tmp_path / "kael_runs"

    def test_does_not_create(self, tmp_path: Path) -> None:
        runs_root(cwd=tmp_path)
        assert not (tmp_path / "kael_runs").exists()


class TestIsRunDir:
    def test_true_for_run_json(self, tmp_path: Path) -> None:
        run = tmp_path / "scan"
        run.mkdir()
        (run / "run.json").write_text("{}", encoding="utf-8")
        assert is_run_dir(run) is True

    def test_false_for_folder(self, tmp_path: Path) -> None:
        folder = tmp_path / "folder"
        folder.mkdir()
        (folder / "sub").mkdir()
        assert is_run_dir(folder) is False

    def test_false_for_missing(self, tmp_path: Path) -> None:
        assert is_run_dir(tmp_path / "nope") is False


class TestIsFolderDir:
    def test_true_with_sentinel(self, tmp_path: Path) -> None:
        folder = tmp_path / "f"
        folder.mkdir()
        (folder / FOLDER_SENTINEL).touch()
        assert is_folder_dir(folder) is True

    def test_true_for_populated_directory_without_sentinel(self, tmp_path: Path) -> None:
        folder = tmp_path / "f"
        folder.mkdir()
        (folder / "sub").mkdir()
        assert is_folder_dir(folder) is True

    def test_false_for_run_dir(self, tmp_path: Path) -> None:
        run = tmp_path / "r"
        run.mkdir()
        (run / "run.json").write_text("{}", encoding="utf-8")
        assert is_folder_dir(run) is False

    def test_false_for_completely_empty_directory(self, tmp_path: Path) -> None:
        folder = tmp_path / "empty"
        folder.mkdir()
        # Empty dirs are ambiguous (could be a failed run before run.json
        # was written). Conservative default: not a folder.
        assert is_folder_dir(folder) is False

    def test_false_for_missing(self, tmp_path: Path) -> None:
        assert is_folder_dir(tmp_path / "nope") is False
