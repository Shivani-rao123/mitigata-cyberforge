"""
tests/common/test_flag_patterns.py

Unit tests for common/flag_patterns.py's FLAG_PATTERNS regex.
"""

from common.flag_patterns import FLAG_PATTERNS

_PATTERN = FLAG_PATTERNS["ctf_style_flag"][0]


def test_matches_classic_flag_format():
    assert _PATTERN.search("FLAG{abc123}")


def test_matches_lowercase_and_mixed_case():
    assert _PATTERN.search("flag{abc123}")
    assert _PATTERN.search("Flag{abc123}")


def test_matches_other_common_prefixes():
    for text in ["CTF{abc}", "HTB{abc}", "THM{abc}", "picoCTF{abc}"]:
        assert _PATTERN.search(text), f"expected a match for {text!r}"


def test_does_not_match_an_unrelated_prefix():
    assert not _PATTERN.search("function(){return 1}")
    assert not _PATTERN.search("banner{not_a_flag_prefix}")


def test_does_not_match_an_empty_or_whitespace_only_body():
    assert not _PATTERN.search("flag{ }")
    assert not _PATTERN.search("flag{}")
