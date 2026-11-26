"""Module 6: Output Guardrails.

Validates LLM-generated responses before returning them to users.
Checks:
1. Sensitive information leakage (API keys, private keys, database credentials, internal system prompts).
2. Harmful or disallowed output according to configurable policies (e.g. system commands `rm -rf`, exploit scripts).
3. PII leakage in the output.
4. Response formatting and policy integrity.

If validation fails, blocks or flags the response and provides a safe fallback message.
"""

import re
from typing import List, Tuple
from pydantic import BaseModel, Field
from app.detectors import ThreatCategory
from app.detectors.pii_detector import PIIDetector


class OutputValidationResult(BaseModel):
    """Result of LLM output guardrail inspection."""
    is_safe: bool = Field(default=True, description="True if output complies with all policies")
    threat_category: ThreatCategory = Field(default=ThreatCategory.NONE, description="Category of output violation")
    sanitized_output: str = Field(..., description="Safe response to return to the caller")
    violations: List[str] = Field(default_factory=list, description="List of detected policy violations")


class OutputGuardrails:
    """Inspects and filters LLM-generated text before sending to client."""

    def __init__(self):
        self.pii_detector = PIIDetector()

        # Secret / Credential / Leakage Patterns
        self._leakage_patterns: List[Tuple[re.Pattern, str]] = [
            # AWS / Cloud Keys
            (re.compile(r"\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}\b"), "Cloud Access Key ID leakage"),
            (re.compile(r"\bghp_[A-Za-z0-9_]{36,255}\b"), "GitHub Personal Access Token leakage"),
            (re.compile(r"\b(sk-[a-zA-Z0-9]{20,48})\b"), "AI API Secret Key leakage"),
            (re.compile(r"-----BEGIN\s+(RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----"), "Private cryptographic key leakage"),

            # Database Connection Strings with Passwords
            (re.compile(r"(postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+", re.IGNORECASE), "Database connection URI with credentials leakage"),

            # Internal System Prompt Leakage
            (re.compile(r"\b(You\s+are\s+a\s+helpful\s+security\s+gateway\s+model|Internal\s+System\s+Directive\s*#)", re.IGNORECASE), "Internal system prompt disclosure in output"),
        ]

        # Harmful / Dangerous system execution recommendations
        self._harmful_output_patterns: List[Tuple[re.Pattern, str]] = [
            (re.compile(r"\b(rm\s+-rf\s+[/~]|format\s+[c-z]:\s+/fs|del\s+/f\s+/s\s+/q\s+c:\\)\b", re.IGNORECASE), "Destructive file system command in output"),
            (re.compile(r"\b(curl|wget)\s+https?://[^\s|]+\s*\|\s*(ba)?sh\b", re.IGNORECASE), "Unverified remote script pipe execution recommendation"),
            (re.compile(r"\b(chmod\s+777\s+[-R]?\s*/)\b", re.IGNORECASE), "Unsafe global permission elevation recommendation"),
        ]

    def validate(self, output_text: str) -> OutputValidationResult:
        """Validate LLM-generated text against output security guardrails."""
        if not output_text:
            return OutputValidationResult(
                is_safe=True,
                threat_category=ThreatCategory.NONE,
                sanitized_output="",
                violations=[]
            )

        violations: List[str] = []

        # 1. Check for secret / key / credential leaks
        for pattern, desc in self._leakage_patterns:
            if pattern.search(output_text):
                violations.append(desc)

        if violations:
            return OutputValidationResult(
                is_safe=False,
                threat_category=ThreatCategory.OUTPUT_LEAKAGE,
                sanitized_output="[BLOCKED: The response contained sensitive system credentials or secret information and has been redacted by security policy.]",
                violations=violations
            )

        # 2. Check for harmful executable commands
        for pattern, desc in self._harmful_output_patterns:
            if pattern.search(output_text):
                violations.append(desc)

        if violations:
            return OutputValidationResult(
                is_safe=False,
                threat_category=ThreatCategory.OUTPUT_POLICY_VIOLATION,
                sanitized_output="[BLOCKED: The generated response violated output security policy regarding dangerous commands.]",
                violations=violations
            )

        # 3. Check for inadvertent PII in the generated response
        pii_result = self.pii_detector.mask_pii(output_text)
        if pii_result.has_pii:
            # Mask PII in the response before returning
            return OutputValidationResult(
                is_safe=True,
                threat_category=ThreatCategory.PII,
                sanitized_output=pii_result.masked_text,
                violations=[f"Output contained PII ({', '.join(pii_result.detected_types)}) which was automatically masked."]
            )

        return OutputValidationResult(
            is_safe=True,
            threat_category=ThreatCategory.NONE,
            sanitized_output=output_text,
            violations=[]
        )
