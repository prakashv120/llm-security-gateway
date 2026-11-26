"""Module 7: PostgreSQL Security Logging Models.

Defines the SecurityLog database entity for recording all inbound requests,
security analysis, risk metrics, and outcomes.
Guarantees that raw passwords, secrets, and unmasked PII are NEVER persisted.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    Index
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def utc_now():
    """Return current timestamp in UTC timezone."""
    return datetime.now(timezone.utc)


class SecurityLog(Base):
    """Database entity storing audit records of LLM gateway transactions."""
    __tablename__ = "security_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Security Analysis
    threat_category = Column(String(64), nullable=False, index=True)
    risk_score = Column(Float, nullable=False, index=True)
    security_decision = Column(String(32), nullable=False, index=True)

    # PII Tracking
    pii_detected = Column(Boolean, nullable=False, default=False)
    pii_types = Column(String(255), nullable=True)  # Comma-separated list of types (e.g. EMAIL, PHONE)

    # Sanitized Context
    prompt_summary = Column(Text, nullable=True)  # Masked and truncated, NEVER raw unmasked PII
    reasons = Column(Text, nullable=True)

    # Processing Details
    processing_status = Column(String(64), nullable=False, index=True)  # ALLOWED, BLOCKED_INPUT, BLOCKED_OUTPUT, LLM_ERROR
    model_used = Column(String(64), nullable=True)
    latency_ms = Column(Float, nullable=False, default=0.0)

    __table_args__ = (
        Index("idx_security_logs_decision_threat", "security_decision", "threat_category"),
        Index("idx_security_logs_timestamp", "timestamp"),
    )

    def to_dict(self):
        """Convert log entity to dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "threat_category": self.threat_category,
            "risk_score": self.risk_score,
            "security_decision": self.security_decision,
            "pii_detected": self.pii_detected,
            "pii_types": self.pii_types.split(",") if self.pii_types else [],
            "prompt_summary": self.prompt_summary,
            "reasons": self.reasons.split("; ") if self.reasons else [],
            "processing_status": self.processing_status,
            "model_used": self.model_used,
            "latency_ms": self.latency_ms
        }
