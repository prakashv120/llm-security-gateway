"""Base interface and data models for security threat detectors."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """Categorization of detected security threats."""
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    PII = "PII"
    OUTPUT_LEAKAGE = "OUTPUT_LEAKAGE"
    OUTPUT_POLICY_VIOLATION = "OUTPUT_POLICY_VIOLATION"


class DetectionResult(BaseModel):
    """Structured result returned by any security detector."""
    threat_detected: bool = Field(default=False, description="True if a threat pattern was identified")
    threat_category: ThreatCategory = Field(default=ThreatCategory.NONE, description="Category of threat")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Calculated risk score between 0.0 and 1.0")
    matched_patterns: List[str] = Field(default_factory=list, description="Identifiers of matched signatures or rules")
    explanation: str = Field(default="", description="Detailed human-readable explanation of the finding")


class BaseDetector(ABC):
    """Abstract base class for all security detectors.
    Allows seamlessly plugging in ML/classifier detectors in the future alongside rule-based engines.
    """

    @abstractmethod
    def detect(self, text: str) -> DetectionResult:
        """Analyze the input text and return a DetectionResult."""
        pass
