"""Tests for Module 6: Output Guardrails."""

import pytest
from app.security.output_guardrails import OutputGuardrails
from app.detectors import ThreatCategory


@pytest.fixture
def guardrails():
    return OutputGuardrails()


def test_safe_normal_output(guardrails):
    """Benign text passes output guardrail without changes."""
    text = "Here is the summary of the requested document: Machine learning is fascinating."
    res = guardrails.validate(text)
    assert res.is_safe
    assert res.threat_category == ThreatCategory.NONE
    assert res.sanitized_output == text


def test_detect_cloud_credential_leak(guardrails):
    """Output leaking AWS access keys must be blocked."""
    text = "Your API key is AKIA1234567890ABCDEF and your bucket is ready."
    res = guardrails.validate(text)
    assert not res.is_safe
    assert res.threat_category == ThreatCategory.OUTPUT_LEAKAGE
    assert "[BLOCKED:" in res.sanitized_output
    assert "AKIA1234567890ABCDEF" not in res.sanitized_output


def test_detect_private_cryptographic_key_leak(guardrails):
    """Output leaking private RSA/SSH keys must be blocked."""
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...==\n-----END RSA PRIVATE KEY-----"
    res = guardrails.validate(text)
    assert not res.is_safe
    assert res.threat_category == ThreatCategory.OUTPUT_LEAKAGE
    assert "[BLOCKED:" in res.sanitized_output


def test_detect_database_connection_leak(guardrails):
    """Output leaking database connection string with password must be blocked."""
    text = "Connected using postgres://postgres:SecretPassword123@localhost:5432/production_db"
    res = guardrails.validate(text)
    assert not res.is_safe
    assert res.threat_category == ThreatCategory.OUTPUT_LEAKAGE
    assert "[BLOCKED:" in res.sanitized_output


def test_detect_destructive_system_commands(guardrails):
    """Output recommending dangerous root file system deletion must be blocked."""
    text = "To fix the system, run `rm -rf /` in your terminal."
    res = guardrails.validate(text)
    assert not res.is_safe
    assert res.threat_category == ThreatCategory.OUTPUT_POLICY_VIOLATION
    assert "[BLOCKED:" in res.sanitized_output


def test_mask_pii_in_output(guardrails):
    """PII accidentally present in LLM response should be masked."""
    text = "The user's contact email is employee@external.com."
    res = guardrails.validate(text)
    assert res.is_safe
    assert res.threat_category == ThreatCategory.PII
    assert "employee@external.com" not in res.sanitized_output
    assert "[REDACTED_EMAIL]" in res.sanitized_output
