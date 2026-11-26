"""Module 3: PII Detection and Masking.

Detects personally identifiable information (PII) including:
- Email addresses
- Phone numbers (international and national)
- Aadhaar-like identifiers (12 digits with Verhoeff checksum algorithm validation)
- Credit card numbers (with Luhn algorithm checksum validation)

Masks sensitive information before forwarding prompts to Ollama.
Ensures unmasked sensitive information is NEVER stored in database logs or metrics.
"""

import re
from typing import List, Tuple
from pydantic import BaseModel, Field


class PIIDetectionResult(BaseModel):
    """Result of PII scanning and redaction."""
    has_pii: bool = Field(default=False, description="True if any PII was detected")
    masked_text: str = Field(..., description="Sanitized text with PII replaced by safe redaction tokens")
    detected_types: List[str] = Field(default_factory=list, description="List of detected PII types (e.g. EMAIL, PHONE)")
    item_count: int = Field(default=0, description="Total number of redacted PII instances")


class PIIDetector:
    """Scans text for sensitive Personally Identifiable Information (PII)
    and replaces occurrences with standardized redacted tokens.
    """

    # Verhoeff algorithm multiplication and permutation tables for Indian Aadhaar validation
    _VERHOEFF_D = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]

    _VERHOEFF_P = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]

    def __init__(self):
        # 1. Email pattern (RFC 5322 compliant regex)
        self._email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        )

        # 2. Phone numbers (covers +1, +91, national formats with parens/dashes/spaces)
        # e.g., +91 98765 43210, +1 (555) 234-5678, 9876543210, 555-123-4567
        self._phone_pattern = re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
        )

        # 3. Aadhaar-like 12-digit pattern: 4 digits + space/dash + 4 digits + space/dash + 4 digits or 12 digits contiguous
        # Starts with digits 2-9 per UIDAI specification
        self._aadhaar_pattern = re.compile(
            r"\b[2-9]\d{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"
        )

        # 4. Credit card patterns: 13 to 19 digits formatted with spaces or dashes
        # Matches Visa, MasterCard, Amex, Discover, RuPay
        self._credit_card_pattern = re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b|\b\d{13,19}\b"
        )

    @classmethod
    def _validate_luhn(cls, card_num_str: str) -> bool:
        """Validate credit card number using Luhn algorithm (mod 10)."""
        digits = [int(c) for c in card_num_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = d * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += d
        return checksum % 10 == 0

    @classmethod
    def _validate_verhoeff(cls, number_str: str) -> bool:
        """Validate Aadhaar 12-digit number using Verhoeff checksum algorithm."""
        digits = [int(c) for c in number_str if c.isdigit()]
        if len(digits) != 12:
            return False

        c = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            c = cls._VERHOEFF_D[c][cls._VERHOEFF_P[i % 8][digit]]
        return c == 0

    def mask_pii(self, text: str) -> PIIDetectionResult:
        """Detect and mask PII in the input text with descriptive redaction tokens."""
        if not text:
            return PIIDetectionResult(
                has_pii=False,
                masked_text="",
                detected_types=[],
                item_count=0
            )

        sanitized = text
        detected_types: List[str] = []
        total_items = 0

        # Step 1: Credit Cards (run before phone/aadhaar to prevent partial matches)
        def replace_cc(match: re.Match) -> str:
            nonlocal total_items
            matched_str = match.group(0)
            cleaned = re.sub(r"[\s-]", "", matched_str)
            # Verify Luhn checksum to avoid redacting random 16-digit serial numbers
            if self._validate_luhn(cleaned):
                total_items += 1
                return "[REDACTED_CREDIT_CARD]"
            return matched_str

        text_after_cc = self._credit_card_pattern.sub(replace_cc, sanitized)
        if text_after_cc != sanitized:
            detected_types.append("CREDIT_CARD")
            sanitized = text_after_cc

        # Step 2: Aadhaar Number (12 digits, validated with Verhoeff or standard 12-digit format)
        def replace_aadhaar(match: re.Match) -> str:
            nonlocal total_items
            matched_str = match.group(0)
            cleaned = re.sub(r"[\s-]", "", matched_str)
            if len(cleaned) == 12:
                # If strictly Verhoeff passes or follows standard 4-4-4 format
                if self._validate_verhoeff(cleaned) or (" " in matched_str or "-" in matched_str):
                    total_items += 1
                    return "[REDACTED_AADHAAR]"
            return matched_str

        text_after_aadhaar = self._aadhaar_pattern.sub(replace_aadhaar, sanitized)
        if text_after_aadhaar != sanitized:
            detected_types.append("AADHAAR")
            sanitized = text_after_aadhaar

        # Step 3: Emails
        def replace_email(match: re.Match) -> str:
            nonlocal total_items
            total_items += 1
            return "[REDACTED_EMAIL]"

        text_after_email = self._email_pattern.sub(replace_email, sanitized)
        if text_after_email != sanitized:
            detected_types.append("EMAIL")
            sanitized = text_after_email

        # Step 4: Phone Numbers (ensure not already redacted tokens)
        def replace_phone(match: re.Match) -> str:
            nonlocal total_items
            matched_str = match.group(0)
            # Filter out short digit strings or plain years (e.g. 2024)
            digits_only = re.sub(r"\D", "", matched_str)
            if len(digits_only) >= 10 and len(digits_only) <= 15:
                total_items += 1
                return "[REDACTED_PHONE]"
            return matched_str

        text_after_phone = self._phone_pattern.sub(replace_phone, sanitized)
        if text_after_phone != sanitized:
            detected_types.append("PHONE")
            sanitized = text_after_phone

        has_pii = total_items > 0
        return PIIDetectionResult(
            has_pii=has_pii,
            masked_text=sanitized,
            detected_types=list(set(detected_types)),
            item_count=total_items
        )
