"""
tests/common/test_redact.py

Unit tests for common/redact.py — shared by the regex-based and
gitleaks-backed secret checks in agents/binary/agent.py, and the
jsluice-based secret check in agents/web/agent.py.
"""

from common.redact import redact


def test_long_secret_keeps_prefix_and_suffix_masks_middle():
    result = redact("AKIAABCDEFGHIJKLMNOP")
    assert result.startswith("AKIA")
    assert result.endswith("MNOP")
    assert "*" in result
    assert len(result) == len("AKIAABCDEFGHIJKLMNOP")


def test_short_secret_is_fully_masked():
    result = redact("abcdefgh")  # exactly keep*2 (4*2=8) chars
    assert result == "*" * 8


def test_very_short_secret_is_fully_masked_not_negative_length():
    result = redact("ab")
    assert result == "**"


def test_empty_secret_returns_empty_string():
    assert redact("") == ""


def test_custom_keep_length():
    result = redact("1234567890", keep=2)
    assert result == "12******90"


def test_never_reveals_more_than_the_edges():
    secret = "super-secret-password-value"
    result = redact(secret)
    middle = result[4:-4]
    assert set(middle) == {"*"}
