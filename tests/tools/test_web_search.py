"""Tests for the Perplexity-backed web_search tool (mirrors exploit_search tests)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from kael.tools.web_search.tool import _do_search


class TestWebSearch:
    def test_empty_query_returns_error(self) -> None:
        result = _do_search("")
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    def test_whitespace_query_returns_error(self) -> None:
        result = _do_search("   ")
        assert result["success"] is False

    def test_missing_api_key_returns_error(self) -> None:
        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = None
            result = _do_search("test query")
        assert result["success"] is False
        assert "not configured" in result["error"]

    @patch("kael.tools.web_search.tool.requests.post")
    def test_successful_search(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Here is what I found..."}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("How does XSS work?")

        assert result["success"] is True
        assert result["query"] == "How does XSS work?"
        assert "found" in result["content"]
        # Verify the request was correctly shaped
        call_args = mock_post.call_args
        assert call_args.kwargs["headers"]["Authorization"] == "Bearer test-key"
        payload = call_args.kwargs["json"]
        assert payload["model"] == "sonar-reasoning-pro"
        assert len(payload["messages"]) == 2  # system + user
        assert payload["messages"][0]["role"] == "system"
        assert "cybersecurity" in payload["messages"][0]["content"].lower()

    @patch("kael.tools.web_search.tool.requests.post")
    def test_client_error_returns_refine_message(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_error = MagicMock(spec=requests.Response)
        mock_error.status_code = 400
        http_error = requests.exceptions.HTTPError("HTTP 400")
        http_error.response = mock_error
        mock_response.raise_for_status.side_effect = http_error
        mock_post.return_value = mock_response

        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("x")

        assert result["success"] is False
        assert "rejected" in result["error"].lower()

    @patch("kael.tools.web_search.tool.requests.post")
    def test_5xx_returns_unavailable_message(self, mock_post: MagicMock) -> None:
        mock_response = MagicMock()
        mock_error = MagicMock(spec=requests.Response)
        mock_error.status_code = 503
        http_error = requests.exceptions.HTTPError("HTTP 503")
        http_error.response = mock_error
        mock_response.raise_for_status.side_effect = http_error
        mock_post.return_value = mock_response

        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("x")

        assert result["success"] is False
        assert "unavailable" in result["error"].lower()

    @patch("kael.tools.web_search.tool.requests.post")
    def test_timeout_returns_error(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = requests.exceptions.Timeout()
        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("x")
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @patch("kael.tools.web_search.tool.requests.post")
    def test_network_error_returns_error(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = requests.exceptions.ConnectionError()
        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("x")
        assert result["success"] is False
        assert "network" in result["error"].lower()

    @patch("kael.tools.web_search.tool.requests.post")
    def test_unexpected_response_shape(self, mock_post: MagicMock) -> None:
        """API returns malformed JSON: missing 'choices' key."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"unexpected": "shape"}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("x")
        assert result["success"] is False
        assert "unexpected" in result["error"].lower()

    @patch("kael.tools.web_search.tool.requests.post")
    def test_choices_empty_list(self, mock_post: MagicMock) -> None:
        """API returns 200 with empty choices list."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": []}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch("kael.tools.web_search.tool.load_settings") as mock_settings:
            mock_settings.return_value.integrations.perplexity_api_key = "test-key"
            result = _do_search("x")
        assert result["success"] is False
