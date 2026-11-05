from secrets_scanner import scan_content


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
