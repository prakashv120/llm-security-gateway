"""Module 1: Prompt Injection Detection.

Identifies malicious instructions such as:
- Ignore previous instructions
- Reveal system prompts
- Override system instructions
- Access confidential information
- Attempt to manipulate the LLM

Implements rule-based and heuristic detection with normalized text analysis.
Designed using an extensible BaseDetector so advanced neural/classifier models
(such as DeBERTa or ONNX models) can be integrated seamlessly.
"""

import re
import unicodedata
from typing import List, Tuple
from app.detectors import BaseDetector, DetectionResult, ThreatCategory


class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection attempts by evaluating syntactic patterns,
    directive overrides, system prompt exfiltration cues, and structural delimiter manipulation.
    """

    def __init__(self):
        # Compiled patterns: (pattern_regex, category_tag, weight, description)
        self._rules: List[Tuple[re.Pattern, str, float, str]] = [
            # 1. Direct Instruction Overrides / Context Reset
            (
                re.compile(
                    r"\b(ignore|disregard|forget|bypass|override|drop|discard|cancel)\s+(all\s+)?(previous|prior|above|past|initial|system)\s+(instructions?|prompts?|rules?|directives?|commands?|guidelines?)",
                    re.IGNORECASE
                ),
                "INSTRUCTION_OVERRIDE",
                0.95,
                "Explicit directive to ignore or override prior instructions"
            ),
            (
                re.compile(
                    r"\b(reset|clear)\s+(the\s+)?(context|memory|instructions|system\s+state|conversation)\b",
                    re.IGNORECASE
                ),
                "CONTEXT_RESET",
                0.80,
                "Attempt to reset LLM conversation context or system state"
            ),
            (
                re.compile(
                    r"\bdo\s+not\s+follow\s+(any\s+)?(previous|initial|system)\s+instructions\b",
                    re.IGNORECASE
                ),
                "INSTRUCTION_NEGATION",
                0.90,
                "Instruction to refuse adherence to system directives"
            ),

            # 2. System Prompt & Internal Configuration Exfiltration
            (
                re.compile(
                    r"\b(reveal|show|print|display|repeat|output|leak|expose|tell\s+me|give\s+me)\s+(me\s+)?(your\s+|the\s+)?(entire\s+|full\s+|hidden\s+|initial\s+|secret\s+)?(system\s+prompt|system\s+instructions|system\s+message|core\s+prompt|developer\s+mode|internal\s+rules)",
                    re.IGNORECASE
                ),
                "SYSTEM_PROMPT_EXFILTRATION",
                0.95,
                "Request to disclose hidden system prompt or internal instructions"
            ),
            (
                re.compile(
                    r"\bwhat\s+(are|were)\s+(your|the)\s+(original|initial|system|secret)\s+(instructions|prompts?|rules)\b",
                    re.IGNORECASE
                ),
                "SYSTEM_PROMPT_INQUIRY",
                0.85,
                "Inquiry probing for secret foundational system instructions"
            ),
            (
                re.compile(
                    r"\b(output|print)\s+everything\s+(above|prior\s+to\s+this|before\s+this\s+line)\b",
                    re.IGNORECASE
                ),
                "PROMPT_LEAK_DELIMITER",
                0.85,
                "Attempt to dump prior conversational context/prompt"
            ),

            # 3. Confidential / Secret Information Access
            (
                re.compile(
                    r"\b(access|dump|extract|steal|retrieve)\s+(confidential|classified|secret|internal|restricted|private)\s+(data|information|credentials|keys|passwords?|tokens?)\b",
                    re.IGNORECASE
                ),
                "CONFIDENTIAL_DATA_ACCESS",
                0.90,
                "Attempt to extract confidential system data or credentials"
            ),

            # 4. Delimiter Hijacking & Fake Role Spoofing
            (
                re.compile(
                    r"(?:^|\n)\s*(?:\[|\<|\{\#)?\s*(SYSTEM|DEVELOPER|ADMIN|ROOT|ASSISTANT)\s*(?:\]|\>|\:|\#\}|\-{3,})",
                    re.IGNORECASE
                ),
                "DELIMITER_SPOOFING",
                0.80,
                "Attempt to inject fake system/developer role delimiters"
            ),
            (
                re.compile(
                    r"(?:^|\n)\s*---+\s*(BEGIN|START)\s+(SYSTEM|DEVELOPER|INSTRUCTION)\b",
                    re.IGNORECASE
                ),
                "SYSTEM_DELIMITER_BLOCK",
                0.85,
                "Attempt to forge system instruction markdown blocks"
            ),

            # 5. Semantic Manipulation / Maintenance Mode
            (
                re.compile(
                    r"\byou\s+are\s+now\s+in\s+(maintenance|debug|diagnostic|admin|override|god)\s+mode\b",
                    re.IGNORECASE
                ),
                "MAINTENANCE_MODE_SPOOF",
                0.90,
                "Attempt to trigger an unauthorized administrative or debug state"
            ),
            (
                re.compile(
                    r"\bnew\s+instructions\s+follow\s*:\s*(ignore|forget|you\s+are)",
                    re.IGNORECASE
                ),
                "DIRECTIVE_SUBSTITUTION",
                0.85,
                "Explicit attempt to replace active instructions with malicious payload"
            ),
        ]

    def _normalize(self, text: str) -> str:
        """Normalize Unicode characters, collapse excessive spacing, and strip evasion tricks."""
        # Normalize Unicode (NFKD decomposes ligatures and unusual characters)
        normalized = unicodedata.normalize("NFKD", text)
        # Collapse multiple spaces and null bytes
        normalized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", normalized)
        return normalized

    def detect(self, text: str) -> DetectionResult:
        """Scan input text against prompt injection signatures and calculate risk score."""
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
        total_weight = 0.0

        for pattern, tag, weight, desc in self._rules:
            if pattern.search(cleaned_text):
                matched_tags.append(tag)
                descriptions.append(desc)
                if weight > max_weight:
                    max_weight = weight
                total_weight += weight

        # Heuristic scoring: base score is max matching weight, plus compounding increment for multi-rule matches
        if matched_tags:
            # Compound risk if multiple injection indicators hit simultaneously
            compound_risk = max_weight + (0.05 * (len(matched_tags) - 1))
            final_risk = min(1.0, round(compound_risk, 3))

            return DetectionResult(
                threat_detected=True,
                threat_category=ThreatCategory.PROMPT_INJECTION,
                risk_score=final_risk,
                matched_patterns=matched_tags,
                explanation=f"Prompt injection detected ({len(matched_tags)} indicator(s)): {'; '.join(descriptions)}"
            )

        return DetectionResult(
            threat_detected=False,
            threat_category=ThreatCategory.NONE,
            risk_score=0.0,
            matched_patterns=[],
            explanation="No prompt injection patterns detected."
        )
