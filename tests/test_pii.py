"""Tests for Module 3: PII Detection and Masking."""

import pytest
from app.detectors.pii_detector import PIIDetector


@pytest.fixture
def detector():
    return PIIDetector()


def test_email_detection_and_masking(detector):
    """Detect and mask single and multiple email addresses."""
    prompt = "Please send the report to user.name@example.com and contact admin@company.org."
    result = detector.mask_pii(prompt)
    assert result.has_pii
    assert "EMAIL" in result.detected_types
    assert result.item_count == 2
    assert "user.name@example.com" not in result.masked_text
    assert "admin@company.org" not in result.masked_text
    assert "[REDACTED_EMAIL]" in result.masked_text


def test_phone_number_detection_and_masking(detector):
    """Detect and mask various phone number representations."""
    prompts = [
        ("My number is +1 (555) 234-5678, call me.", "[REDACTED_PHONE]"),
        ("Call support at 9876543210 immediately.", "[REDACTED_PHONE]"),
        ("Reach me at +91 98765 43210 for details.", "[REDACTED_PHONE]")
    ]
    for text, expected_token in prompts:
        result = detector.mask_pii(text)
        assert result.has_pii, f"Failed to detect phone in: {text}"
        assert "PHONE" in result.detected_types
        assert expected_token in result.masked_text


def test_aadhaar_like_detection_and_masking(detector):
    """Detect and mask 12-digit Aadhaar-like identifiers."""
    prompt = "My Aadhaar number is 9876 5432 1098, please verify it."
    result = detector.mask_pii(prompt)
    assert result.has_pii
    assert "AADHAAR" in result.detected_types
    assert "9876 5432 1098" not in result.masked_text
    assert "[REDACTED_AADHAAR]" in result.masked_text


def test_credit_card_luhn_validation_and_masking(detector):
    """Detect and mask valid credit card numbers using Luhn checksum."""
    # Standard Luhn-valid test card number (Visa test: 4532 0150 0000 0043)
    valid_card = "4532-0150-0000-0043"
    prompt = f"Charge my card {valid_card} for the booking."
    result = detector.mask_pii(prompt)
    assert result.has_pii
    assert "CREDIT_CARD" in result.detected_types
    assert valid_card not in result.masked_text
    assert "[REDACTED_CREDIT_CARD]" in result.masked_text


def test_mixed_pii_in_single_prompt(detector):
    """Detect multiple distinct PII types within a single paragraph."""
    prompt = "Reach John at john.doe@secure.io or +1-800-555-0199 regarding transaction with card 4532 0150 0000 0043."
    result = detector.mask_pii(prompt)
    assert result.has_pii
    assert set(result.detected_types) == {"EMAIL", "PHONE", "CREDIT_CARD"}
    assert result.item_count == 3
    assert "john.doe@secure.io" not in result.masked_text
    assert "4532 0150 0000 0043" not in result.masked_text


def test_benign_text_no_pii(detector):
    """Ensure normal numbers, years, and words are not falsely masked."""
    prompt = "In 2024, the company grew by 15% across 3 continents."
    result = detector.mask_pii(prompt)
    assert not result.has_pii
    assert result.item_count == 0
    assert result.masked_text == prompt
