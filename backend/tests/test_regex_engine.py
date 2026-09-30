from app.detectors.regex_engine import RegexEngine

engine = RegexEngine()


def test_detects_aws_key():
    findings = engine.scan("my key is AKIAIOSFODNN7EXAMPLE please use it")
    assert any(f.category.value == "cloud_secret" for f in findings)


def test_detects_github_token():
    findings = engine.scan("token: ghp_1234567890abcdef1234567890abcdef1234")
    assert any(f.category.value == "access_token" for f in findings)


def test_detects_private_key_block():
    findings = engine.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----")
    assert any(f.category.value == "private_key" for f in findings)


def test_detects_db_connection_string():
    findings = engine.scan("postgresql://admin:hunter2@db.internal:5432/prod")
    assert any(f.category.value == "database_conn_string" for f in findings)


def test_no_false_positive_on_safe_text():
    findings = engine.scan("Please write me a haiku about autumn leaves falling gently.")
    assert findings == []


def test_redaction_never_leaks_full_secret():
    findings = engine.scan("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].matched_text
