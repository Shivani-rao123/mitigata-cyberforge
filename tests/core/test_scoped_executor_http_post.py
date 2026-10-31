"""
tests/core/test_scoped_executor_http_post.py

Unit tests for RealScopedExecutor.http_post() (added for FR-6 — the
verification engine needs to actually submit a candidate login form's
fields via POST, through the same scope-enforcement path every other
executor method uses). Mocks core.scoped_executor.requests.post
directly, same no-real-network seam test_scoped_executor_crawl_redirects.py
and test_scoped_executor_crawl_page_budget.py already use for GET.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from core.scoped_executor import RealScopedExecutor, ScopeViolation

TARGET_URL = "http://10.10.10.5/login.php"


class _FakeResponse:
    def __init__(self, status_code: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {"Content-Type": "text/html"}

    def iter_content(self, chunk_size: int = 65_536):
        if self._body:
            yield self._body

    def close(self) -> None:
        pass


def _executor(is_in_scope=lambda ip: True) -> RealScopedExecutor:
    return RealScopedExecutor(is_in_scope=is_in_scope, log_scope_check=lambda ip, ok: None)


def test_http_post_sends_data_and_returns_status_headers_body():
    executor = _executor()
    fake_response = _FakeResponse(302, b"Location: /dashboard", headers={"Content-Type": "text/html"})

    with (
        patch("core.scoped_executor.socket.gethostbyname", return_value="10.10.10.5"),
        patch("core.scoped_executor.requests.post", return_value=fake_response) as mock_post,
    ):
        result = executor.http_post(TARGET_URL, {"username": "admin", "password": "admin"})

    assert result["status"] == 302
    assert "dashboard" in result["body"]
    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["data"] == {"username": "admin", "password": "admin"}
    assert kwargs["allow_redirects"] is False


def test_http_post_is_scope_checked_before_sending():
    executor = _executor(is_in_scope=lambda ip: False)

    with patch("core.scoped_executor.socket.gethostbyname", return_value="10.10.10.5"):
        with pytest.raises(ScopeViolation):
            executor.http_post(TARGET_URL, {"username": "admin", "password": "admin"})


def test_http_post_returns_error_dict_on_request_exception():
    executor = _executor()

    with (
        patch("core.scoped_executor.socket.gethostbyname", return_value="10.10.10.5"),
        patch(
            "core.scoped_executor.requests.post",
            side_effect=requests.RequestException("connection refused"),
        ),
    ):
        result = executor.http_post(TARGET_URL, {"username": "admin", "password": "admin"})

    assert result["status"] == 0
    assert "connection refused" in result["error"]
