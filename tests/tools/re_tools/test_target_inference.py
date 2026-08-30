"""Unit tests for target type inference (malware_sample support)."""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_file():
    """Create a temporary file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"test content")
        return f.name


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    import tempfile

    temp_dir = tempfile.mkdtemp()
    return temp_dir


def test_infer_target_type_file(temp_file):
    """Test that files are detected as malware_sample."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type(temp_file)

    assert target_type == "malware_sample"
    assert "target_file" in details
    assert details["target_file"] == str(Path(temp_file).resolve())

    # Cleanup
    Path(temp_file).unlink()


def test_infer_target_type_directory(temp_dir):
    """Test that directories are still detected as local_code."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type(temp_dir)

    assert target_type == "local_code"
    assert "target_path" in details
    assert details["target_path"] == str(Path(temp_dir).resolve())

    # Cleanup
    import shutil

    shutil.rmtree(temp_dir)


def test_infer_target_type_url():
    """Test URL detection."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type("https://example.com")

    assert target_type == "web_application"
    assert "target_url" in details


def test_infer_target_type_repository():
    """Test repository URL detection."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type("https://github.com/user/repo")

    assert target_type == "repository"
    assert "target_repo" in details


def test_infer_target_type_git_ssh():
    """Test git SSH URL detection."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type("git@github.com:user/repo.git")

    assert target_type == "repository"
    assert "target_repo" in details


def test_infer_target_type_ip():
    """Test IP address detection."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type("192.168.1.100")

    assert target_type == "ip_address"
    assert "target_ip" in details


def test_infer_target_type_domain():
    """Test domain name detection."""
    from kael.interface.utils import infer_target_type

    target_type, details = infer_target_type("example.com")

    assert target_type == "web_application"
    assert "target_url" in details


def test_infer_target_type_nonexistent():
    """Test that nonexistent paths are rejected."""
    from kael.interface.utils import infer_target_type

    with pytest.raises(ValueError) as exc_info:
        infer_target_type("/nonexistent/path/file.exe")

    assert "invalid" in str(exc_info.value).lower()


def test_infer_target_type_relative_file(temp_file):
    """Test relative file paths."""
    import os

    from kael.interface.utils import infer_target_type

    # Change to temp directory
    original_cwd = os.getcwd()
    temp_dir = Path(temp_file).parent
    os.chdir(temp_dir)

    try:
        # Use relative path
        relative_path = f"./{Path(temp_file).name}"
        target_type, details = infer_target_type(relative_path)

        assert target_type == "malware_sample"
        assert "target_file" in details
        # Should be resolved to absolute path
        assert Path(details["target_file"]).is_absolute()
    finally:
        os.chdir(original_cwd)
        Path(temp_file).unlink()


def test_infer_target_type_tilde_expansion(
    temp_file,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Test tilde expansion in file paths."""
    import os

    from kael.interface.utils import infer_target_type

    # Use an isolated home so the test never writes to the developer account.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    test_file = home / "test_sample.exe"
    test_file.write_bytes(Path(temp_file).read_bytes())
    Path(temp_file).unlink()

    try:
        target_type, details = infer_target_type("~/test_sample.exe")

        assert target_type == "malware_sample"
        assert "target_file" in details
        assert details["target_file"] == str(test_file)
    finally:
        if test_file.exists():
            test_file.unlink()


def test_collect_local_sources_malware_sample():
    """Test that malware_sample targets are collected correctly."""
    from kael.interface.utils import collect_local_sources

    targets_info = [
        {
            "type": "malware_sample",
            "details": {"target_file": "/path/to/sample.exe", "workspace_subdir": "target_0"},
        }
    ]

    local_sources = collect_local_sources(targets_info)

    assert len(local_sources) == 1
    assert local_sources[0]["source_path"] == "/path/to/sample.exe"
    assert local_sources[0]["workspace_subdir"] == "target_0"
    assert local_sources[0]["is_file"] is True


def test_collect_local_sources_directory():
    """Test that local_code targets still work."""
    from kael.interface.utils import collect_local_sources

    targets_info = [
        {
            "type": "local_code",
            "details": {"target_path": "/path/to/project", "workspace_subdir": "target_0"},
        }
    ]

    local_sources = collect_local_sources(targets_info)

    assert len(local_sources) == 1
    assert local_sources[0]["source_path"] == "/path/to/project"
    assert local_sources[0]["workspace_subdir"] == "target_0"
    assert "is_file" not in local_sources[0] or local_sources[0].get("is_file") is False


def test_collect_local_sources_mixed():
    """Test mixed target types."""
    from kael.interface.utils import collect_local_sources

    targets_info = [
        {
            "type": "local_code",
            "details": {"target_path": "/path/to/project", "workspace_subdir": "target_0"},
        },
        {
            "type": "malware_sample",
            "details": {"target_file": "/path/to/sample.exe", "workspace_subdir": "target_1"},
        },
        {"type": "web_application", "details": {"target_url": "https://example.com"}},
    ]

    local_sources = collect_local_sources(targets_info)

    # Should collect only local sources (code + malware_sample)
    assert len(local_sources) == 2
    assert local_sources[0]["source_path"] == "/path/to/project"
    assert local_sources[1]["source_path"] == "/path/to/sample.exe"
    assert local_sources[1]["is_file"] is True


def test_infer_target_type_empty_string():
    """Test empty string target."""
    from kael.interface.utils import infer_target_type

    with pytest.raises(ValueError) as exc_info:
        infer_target_type("")

    assert "non-empty" in str(exc_info.value).lower()


def test_infer_target_type_whitespace():
    """Test whitespace-only target."""
    from kael.interface.utils import infer_target_type

    with pytest.raises(ValueError) as exc_info:
        infer_target_type("   ")

    assert "non-empty" in str(exc_info.value).lower()


def test_infer_target_type_file_with_spaces(temp_dir):
    """Test file path with spaces."""
    from kael.interface.utils import infer_target_type

    # Create file with spaces in name
    file_with_spaces = Path(temp_dir) / "sample with spaces.exe"
    file_with_spaces.write_bytes(b"test")

    try:
        target_type, details = infer_target_type(str(file_with_spaces))

        assert target_type == "malware_sample"
        assert "target_file" in details
    finally:
        import shutil

        shutil.rmtree(temp_dir)
