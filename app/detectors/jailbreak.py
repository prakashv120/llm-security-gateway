"""Module 2: Jailbreak Detection.

Identifies attempts to bypass LLM safety restrictions such as:
- Pretend you are an unrestricted AI
- Ignore all safety restrictions
- Act as an AI without limitations
- DAN (Do Anything Now), STAN, AIM, and Developer Mode jailbreaks

Distinguishes jailbreak attempts from ordinary prompt injection:
- Prompt Injections target system instructions, prompt leakage, and operational control.
- Jailbreaks specifically attack safety, ethical guidelines, moral constraints, and content filters.
"""

import re
import unicodedata
from typing import List, Tuple
from app.detectors import BaseDetector, DetectionResult, ThreatCategory


class JailbreakDetector(BaseDetector):
    """Detects jailbreak attempts aimed at stripping safety boundaries,
    disabling safety filters, or assuming unrestricted personas.
    """

    def __init__(self):
        # Compiled patterns: (pattern_regex, category_tag, weight, description)
        self._rules: List[Tuple[re.Pattern, str, float, str]] = [
            # 1. Unrestricted AI Personas & Roleplay
            (
                re.compile(
                    r"\b(act|pretend|behave|roleplay|simulate)\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|evil|unconstrained|limitless)\s+(ai|llm|model|assistant|bot)\b",
                    re.IGNORECASE
                ),
                "UNRESTRICTED_AI_PERSONA",
                0.95,
                "Request to assume an unrestricted or unfiltered AI persona"
            ),
            (
                re.compile(
                    r"\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are)\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|limitless)\b",
                    re.IGNORECASE
                ),
                "UNRESTRICTED_IDENTITY_MANDATE",
                0.90,
                "Mandate forcing the model into an unrestricted state"
            ),
            (
                re.compile(
                    r"\b(act\s+as|you\s+are\s+now)\s+(DAN|STAN|AIM|MONGO|DUDE|CHAOS|JAILBREAK)\b",
                    re.IGNORECASE
                ),
                "KNOWN_JAILBREAK_PERSONA",
                0.95,
                "Invocation of known jailbreak personas (DAN, STAN, AIM, etc.)"
            ),
            (
                re.compile(
                    r"\bdo\s+anything\s+now\b",
                    re.IGNORECASE
                ),
                "DAN_MOTTO",
                0.95,
                "DAN ('Do Anything Now') jailbreak trigger phrase"
            ),

            # 2. Safety and Policy Bypass Directives
            (
                re.compile(
                    r"\b(ignore|bypass|disable|remove|circumvent|turn\s+off|disregard)\s+(all\s+)?(safety|ethical|moral|content|legal|openai|anthropic|google|meta)\s+(restrictions?|guidelines?|filters?|rules?|policies?|boundaries?)\b",
                    re.IGNORECASE
                ),
                "SAFETY_FILTER_BYPASS",
                0.95,
                "Explicit directive to bypass safety or ethical policies"
            ),
            (
                re.compile(
                    r"\bwithout\s+(any\s+)?(safety|ethical|moral|content)\s+(restrictions?|filters?|limitations?|censorship)\b",
                    re.IGNORECASE
                ),
                "UNFILTERED_CONDITION",
                0.85,
                "Condition requiring the LLM to operate without safety filters"
            ),
            (
                re.compile(
                    r"\b(have\s+no|with\s+no|without)\s+(limitations?|rules?|boundaries?|censorship|filters?)\b",
                    re.IGNORECASE
                ),
                "NO_LIMITATIONS_PROMPT",
                0.80,
                "Condition asserting the LLM has no limitations or censorship"
            ),

            # 3. Developer Mode / Hypnosis / Hypothetical Exploit Scenarios
            (
                re.compile(
                    r"\benable\s+(developer\s+mode|god\s+mode|jailbreak\s+mode|unfiltered\s+mode)\b",
                    re.IGNORECASE
                ),
                "DEVELOPER_MODE_JAILBREAK",
                0.90,
                "Attempt to trigger simulated developer mode or jailbreak mode"
            ),
            (
                re.compile(
                    r"\bfor\s+hypothetical\s+purposes\s+only\s*,\s*(ignore\s+all\s+rules|pretend\s+you\s+have\s+no\s+safety)\b",
                    re.IGNORECASE
                ),
                "HYPOTHETICAL_BYPASS",
                0.85,
                "Framing policy bypass under the guise of a hypothetical exercise"
            ),
            (
                re.compile(
                    r"\bgenerate\s+two\s+responses\s*:\s*one\s+normal\s+and\s+one\s+(unfiltered|unrestricted|developer|jailbroken)\b",
                    re.IGNORECASE
                ),
                "DUAL_RESPONSE_JAILBREAK",
                0.90,
                "Dual-response jailbreak prompt designed to evade single-answer safety filters"
            ),
            (
                re.compile(
                    r"\bnever\s+say\s+no\b|\balways\s+comply\s+with\s+(every|all)\s+requests?\b",
                    re.IGNORECASE
                ),
                "MANDATORY_COMPLIANCE",
                0.80,
                "Attempt to force unconditional compliance and prohibit safety refusals"
            ),
        ]

    def _normalize(self, text: str) -> str:
        """Normalize Unicode characters, strip control chars, and lower case for uniform parsing."""
        normalized = unicodedata.normalize("NFKD", text)
        normalized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", normalized)
        return normalized

    def detect(self, text: str) -> DetectionResult:
        """Scan input text against jailbreak signatures and calculate jailbreak risk score."""
        if not text or not text.strip():
            return DetectionResult(
                threat_detected=False,
                threat_category=ThreatCategory.NONE,
                risk_score=0.0,
                matched_patterns=[],
                explanation="Input text is empty."
            )

        cleaned_text = self._normalize(text)
        matched_tags: List[str] = []
        descriptions: List[str] = []
        max_weight = 0.0

        for pattern, tag, weight, desc in self._rules:
            if pattern.search(cleaned_text):
                matched_tags.append(tag)
                descriptions.append(desc)
                if weight > max_weight:
                    max_weight = weight

        if matched_tags:
            compound_risk = max_weight + (0.05 * (len(matched_tags) - 1))
            final_risk = min(1.0, round(compound_risk, 3))

            return DetectionResult(
                threat_detected=True,
                threat_category=ThreatCategory.JAILBREAK,
                risk_score=final_risk,
                matched_patterns=matched_tags,
                explanation=f"Jailbreak attempt detected ({len(matched_tags)} indicator(s)): {'; '.join(descriptions)}"
            )

        return DetectionResult(
            threat_detected=False,
            threat_category=ThreatCategory.NONE,
            risk_score=0.0,
            matched_patterns=[],
            explanation="No jailbreak patterns detected."
        )
