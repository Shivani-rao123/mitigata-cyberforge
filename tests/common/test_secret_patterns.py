"""
tests/common/test_secret_patterns.py

Unit tests for common/secret_patterns.py — the shared regex set used by
both agents/binary/agent.py (regex fallback) and core/parsers/katana.py
(JS body secret scan).
"""

from common.secret_patterns import SECRET_PATTERNS


def test_aws_access_key_id_pattern_matches_proper_20_char_key():
    pattern, _ = SECRET_PATTERNS["aws_access_key_id"]
    assert pattern.search("AKIAFAKEEXAMPLE12345")


def test_stripe_secret_key_pattern_matches():
    # Built from two pieces, not one literal, so this obviously-fake
    # test value doesn't trip GitHub's push-protection secret scanner.
    pattern, _ = SECRET_PATTERNS["stripe_secret_key"]
    fake_key = "sk_live_51H8xyzFAKEKEY" + "abcdefghijklmnopqrstuvwxyzABCD12"
    assert pattern.search(fake_key)


def test_private_key_header_pattern_matches():
    pattern, _ = SECRET_PATTERNS["private_key_header"]
    assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")


def test_slack_token_pattern_matches():
    # Built from two pieces, not one literal, so this obviously-fake
    # test value doesn't trip GitHub's push-protection secret scanner.
    pattern, _ = SECRET_PATTERNS["slack_token"]
    fake_token = "xoxb-1234567890-" + "abcdefghijklmnop"
    assert pattern.search(fake_token)


def test_generic_secret_assignment_pattern_matches():
    pattern, _ = SECRET_PATTERNS["generic_secret_assignment"]
    assert pattern.search('api_key = "abcd1234efgh5678"')


def test_patterns_do_not_match_unrelated_text():
    for name, (pattern, _) in SECRET_PATTERNS.items():
        assert not pattern.search("just some ordinary log output, nothing secret here"), name
