from secrets_scanner import scan_content, shannon_entropy, apply_allowlist, SecretFinding


def test_detects_aws_access_key():
    js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
    findings = scan_content(js, "https://example.com/app.js")
    assert any(f.rule_id == "aws-access-key" for f in findings)


def test_detects_stripe_secret():
    prefix = "sk_" + "live_"
    fake = prefix + "a1b2c3d4e5f6g7h8i9j0k1l2m3n"
    js = f'const stripe = Stripe("{fake}");'
    findings = scan_content(js, "https://example.com/checkout.js")
    assert any(f.rule_id == "stripe-secret" for f in findings)


def test_detects_github_token():
    js = 'headers: { Authorization: "token ghp_ABCDEFghijklmnopqrstuvwxyz1234567890" }'
    findings = scan_content(js, "https://example.com/api.js")
    assert any(f.rule_id == "github-token" for f in findings)


def test_detects_hardcoded_password():
    js = '''const config = { password: "SuperS3cretP@ss!" };'''
    findings = scan_content(js, "https://example.com/config.js")
    assert any(f.rule_id == "password-assignment" for f in findings)


def test_detects_internal_url():
    js = 'const API = "http://192.168.1.50:8080/api/v1/users";'
    findings = scan_content(js, "https://example.com/app.js")
    assert any(f.rule_id == "internal-url" for f in findings)


def test_detects_jwt():
    js = 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456"'
    findings = scan_content(js, "https://example.com/auth.js")
    assert any(f.rule_id == "jwt-token" for f in findings)


def test_detects_private_key():
    js = 'var key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."'
    findings = scan_content(js, "https://example.com/crypto.js")
    assert any(f.rule_id == "private-key" for f in findings)


def test_clean_js_no_findings():
    js = 'function add(a, b) { return a + b; }'
    findings = scan_content(js, "https://example.com/util.js")
    assert len(findings) == 0


def test_slack_webhook_detected():
    js = 'const webhook = "https://hooks.slack.com/services/T0123ABC/B0123DEF/abcdef1234567890ghijklmn";'
    findings = scan_content(js, "https://example.com/notify.js")
    assert any(f.rule_id == "slack-webhook" for f in findings)


def test_line_number_correct():
    js = "line1\nline2\nvar key = 'AKIAIOSFODNN7EXAMPLE';\nline4"
    findings = scan_content(js, "test.js")
    aws = [f for f in findings if f.rule_id == "aws-access-key"]
    assert aws and aws[0].line_number == 3


def test_detects_generic_api_key():
    js = 'const config = { api_key: "abcdefghij1234567890" };'
    findings = scan_content(js, "https://example.com/config.js")
    assert any(f.rule_id == "generic-api-key" for f in findings)


def test_detects_azure_storage_key():
    fake_key = "A" * 86 + "=="
    js = f'AccountKey={fake_key}'
    findings = scan_content(js, "https://example.com/storage.js")
    assert any(f.rule_id == "azure-storage-key" for f in findings)


def test_shannon_entropy_high():
    random_looking = "aB3xK9mQ2pL7nR5wT1yU4vE6jH8fC0d"
    ent = shannon_entropy(random_looking)
    assert ent > 4.0


def test_shannon_entropy_low():
    repetitive = "aaaaaaaaaaaaaaaaaaaaaa"
    ent = shannon_entropy(repetitive)
    assert ent < 1.0


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_entropy_detection():
    random_token = "aB3xK9mQ2pL7nR5wT1yU4vE6jH8fC0d"
    js = f'var token = "{random_token}";'
    findings = scan_content(js, "test.js", entropy=True)
    assert any(f.rule_id == "high-entropy-string" for f in findings)


def test_entropy_not_flagged_without_flag():
    random_token = "aB3xK9mQ2pL7nR5wT1yU4vE6jH8fC0d"
    js = f'var token = "{random_token}";'
    findings = scan_content(js, "test.js", entropy=False)
    assert not any(f.rule_id == "high-entropy-string" for f in findings)


def test_allowlist_filters_by_rule_id():
    js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
    findings = scan_content(js, "test.js")
    assert any(f.rule_id == "aws-access-key" for f in findings)
    filtered = apply_allowlist(findings, {"aws-access-key"})
    assert not any(f.rule_id == "aws-access-key" for f in filtered)


def test_allowlist_filters_by_matched_text():
    js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
    findings = scan_content(js, "test.js")
    filtered = apply_allowlist(findings, {"AKIAIOSFODNN7EXAMPLE"})
    assert len(filtered) == 0


def test_empty_allowlist_keeps_all():
    js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
    findings = scan_content(js, "test.js")
    filtered = apply_allowlist(findings, set())
    assert len(filtered) == len(findings)


def test_empty_content_no_findings():
    findings = scan_content("", "test.js")
    assert len(findings) == 0


def test_long_match_truncated():
    prefix = "sk_" + "live_"
    long_key = prefix + "a" * 300
    js = f'key = "{long_key}"'
    findings = scan_content(js, "test.js")
    stripe = [f for f in findings if f.rule_id == "stripe-secret"]
    assert stripe
    assert len(stripe[0].matched_text) <= 203
