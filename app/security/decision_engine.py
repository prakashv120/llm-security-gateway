"""Module 4 & Input Guardrails: Security Decision Engine & Input Validation.

Orchestrates:
1. Input normalization and sanity checks.
2. Prompt injection detection.
3. Jailbreak detection.
4. PII detection and masking.
5. Risk aggregation and threshold-based decision making.

Decisions:
- ALLOW: Safe prompt, low risk.
- MASK: Contains PII but safe otherwise; forward masked prompt.
- REVIEW: Moderate risk, requires inspection/flagged for human review.
- BLOCK: High risk threat (injection/jailbreak) detected; do not send to LLM.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from app.config.settings import settings
from app.detectors import ThreatCategory
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.pii_detector import PIIDetector, PIIDetectionResult


class SecurityDecision(str, Enum):
    """Enforceable security decisions."""
    ALLOW = "ALLOW"
    MASK = "MASK"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class SecurityDecisionResult(BaseModel):
    """Comprehensive result of the security decision engine."""
    decision: SecurityDecision = Field(..., description="The final security gate decision")
    overall_risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall consolidated risk score")
    threat_detected: bool = Field(default=False, description="True if any threat is identified")
    primary_threat: ThreatCategory = Field(default=ThreatCategory.NONE, description="Main threat category")
    reasons: List[str] = Field(default_factory=list, description="List of reasons and detected signatures")
    pii_result: PIIDetectionResult = Field(..., description="PII detection and masking details")
    sanitized_prompt: str = Field(..., description="Prompt to send to LLM (masked if PII is present)")


class SecurityDecisionEngine:
    """Centralized security engine evaluating incoming prompts against multiple guardrails."""

    def __init__(
        self,
        allow_threshold: Optional[float] = None,
        review_threshold: Optional[float] = None
    ):
        self.allow_threshold = allow_threshold if allow_threshold is not None else settings.THRESHOLD_ALLOW
        self.review_threshold = review_threshold if review_threshold is not None else settings.THRESHOLD_REVIEW

        self.injection_detector = PromptInjectionDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.pii_detector = PIIDetector()

    def evaluate(self, prompt: str) -> SecurityDecisionResult:
        """Evaluate prompt through all detectors, calculate aggregated risk, and make a decision."""
        # 1. Validate prompt length
        if len(prompt) > settings.MAX_PROMPT_LENGTH:
            return SecurityDecisionResult(
                decision=SecurityDecision.BLOCK,
                overall_risk_score=1.0,
                threat_detected=True,
                primary_threat=ThreatCategory.PROMPT_INJECTION,
                reasons=[f"Prompt length ({len(prompt)} characters) exceeds maximum limit of {settings.MAX_PROMPT_LENGTH}"],
                pii_result=PIIDetectionResult(has_pii=False, masked_text="", detected_types=[], item_count=0),
                sanitized_prompt=""
            )

        # 2. PII Detection & Masking
        pii_result = self.pii_detector.mask_pii(prompt)
        prompt_for_llm = pii_result.masked_text if settings.MASK_PII_BEFORE_FORWARDING else prompt

        # 3. Detect Prompt Injection
        injection_result = self.injection_detector.detect(prompt)

        # 4. Detect Jailbreak Attempts
        jailbreak_result = self.jailbreak_detector.detect(prompt)

        # 5. Risk Aggregation & Decision Logic
        reasons: List[str] = []
        threat_detected = False
        primary_threat = ThreatCategory.NONE

        # Calculate composite risk score
        # Priority to maximum threat score observed
        scores = [injection_result.risk_score, jailbreak_result.risk_score]
        overall_risk = max(scores)

        # Determine primary threat
        if jailbreak_result.risk_score >= injection_result.risk_score and jailbreak_result.threat_detected:
            primary_threat = ThreatCategory.JAILBREAK
            threat_detected = True
            reasons.append(jailbreak_result.explanation)
        elif injection_result.threat_detected:
            primary_threat = ThreatCategory.PROMPT_INJECTION
            threat_detected = True
            reasons.append(injection_result.explanation)

        if pii_result.has_pii:
            reasons.append(f"PII detected ({pii_result.item_count} items): {', '.join(pii_result.detected_types)}")

        # Decision Matrix:
        # High Risk (>= review_threshold, e.g. >= 0.70) -> BLOCK
        # Medium Risk (allow_threshold <= risk < review_threshold, e.g. 0.30 to 0.69) -> REVIEW
        # Low Risk (< allow_threshold):
        #   If PII is present -> MASK (safe prompt with masked sensitive entities)
        #   Else -> ALLOW
        if overall_risk >= self.review_threshold:
            decision = SecurityDecision.BLOCK
        elif overall_risk >= self.allow_threshold:
            decision = SecurityDecision.REVIEW
        elif pii_result.has_pii:
            decision = SecurityDecision.MASK
        else:
            decision = SecurityDecision.ALLOW

        return SecurityDecisionResult(
            decision=decision,
            overall_risk_score=overall_risk,
            threat_detected=threat_detected or pii_result.has_pii,
            primary_threat=primary_threat,
            reasons=reasons,
            pii_result=pii_result,
            sanitized_prompt=prompt_for_llm
        )
