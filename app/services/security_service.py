"""Security service: analyzes prompts for threats without LLM invocation."""

import time
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repository import SecurityRepository
from app.schemas.response import DetectResponse
from app.security.decision_engine import SecurityDecisionEngine


class SecurityService:
    """Service providing standalone prompt threat analysis and auditing."""

    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.decision_engine = SecurityDecisionEngine()
        self.db_session = db_session

    async def detect_threats(self, prompt: str) -> DetectResponse:
        """Inspect prompt for injections, jailbreaks, and PII, logging the audit record."""
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())

        # Evaluate prompt through decision engine
        decision_result = self.decision_engine.evaluate(prompt)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Log inspection to database if session is present
        if self.db_session:
            repository = SecurityRepository(self.db_session)
            await repository.create_log(
                request_id=request_id,
                threat_category=decision_result.primary_threat.value,
                risk_score=decision_result.overall_risk_score,
                security_decision=decision_result.decision.value,
                pii_detected=decision_result.pii_result.has_pii,
                pii_types=decision_result.pii_result.detected_types,
                prompt_summary=decision_result.sanitized_prompt,
                reasons=decision_result.reasons,
                processing_status="INSPECTION_ONLY",
                model_used=None,
                latency_ms=round(elapsed_ms, 2)
            )

        return DetectResponse(
            request_id=request_id,
            threat_detected=decision_result.threat_detected,
            threat_category=decision_result.primary_threat.value,
            risk_score=decision_result.overall_risk_score,
            decision=decision_result.decision.value,
            pii_detected=decision_result.pii_result.has_pii,
            pii_types=decision_result.pii_result.detected_types,
            masked_prompt=decision_result.sanitized_prompt if decision_result.pii_result.has_pii else None,
            reasons=decision_result.reasons
        )
