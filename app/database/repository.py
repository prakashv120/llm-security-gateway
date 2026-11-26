"""Module 7 & 8: PostgreSQL Security Log Repository and Statistics.

Encapsulates database persistence for security records and statistical aggregations:
- Total requests
- Allowed requests
- Blocked requests
- Prompt injection attempts
- Jailbreak attempts
- PII detection incidents
- Average risk score
"""

from typing import List, Optional, Dict, Any
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import SecurityLog


class SecurityRepository:
    """Repository handling all CRUD and statistical aggregation operations on SecurityLog."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_log(
        self,
        request_id: str,
        threat_category: str,
        risk_score: float,
        security_decision: str,
        pii_detected: bool,
        pii_types: List[str],
        prompt_summary: str,
        reasons: List[str],
        processing_status: str,
        model_used: Optional[str] = None,
        latency_ms: float = 0.0
    ) -> SecurityLog:
        """Create and commit a new security log entry."""
        log_entry = SecurityLog(
            request_id=request_id,
            threat_category=threat_category,
            risk_score=risk_score,
            security_decision=security_decision,
            pii_detected=pii_detected,
            pii_types=",".join(pii_types) if pii_types else None,
            prompt_summary=prompt_summary[:500] if prompt_summary else "",  # Enforce truncation
            reasons="; ".join(reasons) if reasons else "",
            processing_status=processing_status,
            model_used=model_used,
            latency_ms=latency_ms
        )
        self.session.add(log_entry)
        await self.session.commit()
        await self.session.refresh(log_entry)
        return log_entry

    async def get_logs(
        self,
        skip: int = 0,
        limit: int = 50,
        decision: Optional[str] = None,
        threat_category: Optional[str] = None
    ) -> List[SecurityLog]:
        """Retrieve paginated security logs with optional filters."""
        query = select(SecurityLog).order_by(desc(SecurityLog.timestamp))

        if decision:
            query = query.where(SecurityLog.security_decision == decision.upper())
        if threat_category:
            query = query.where(SecurityLog.threat_category == threat_category.upper())

        query = query.offset(skip).limit(min(limit, 200))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_stats(self) -> Dict[str, Any]:
        """Aggregate security metrics across all recorded requests."""
        # Query total count and average risk score
        total_stmt = select(
            func.count(SecurityLog.id).label("total_requests"),
            func.coalesce(func.avg(SecurityLog.risk_score), 0.0).label("avg_risk_score")
        )
        total_res = (await self.session.execute(total_stmt)).one()
        total_requests = total_res.total_requests or 0
        avg_risk_score = round(float(total_res.avg_risk_score or 0.0), 4)

        if total_requests == 0:
            return {
                "total_requests": 0,
                "allowed_requests": 0,
                "blocked_requests": 0,
                "prompt_injection_attempts": 0,
                "jailbreak_attempts": 0,
                "pii_detection_incidents": 0,
                "average_risk_score": 0.0
            }

        # Query counts for decisions and threat categories
        allowed_stmt = select(func.count(SecurityLog.id)).where(SecurityLog.security_decision.in_(["ALLOW", "MASK"]))
        blocked_stmt = select(func.count(SecurityLog.id)).where(SecurityLog.security_decision == "BLOCK")
        injection_stmt = select(func.count(SecurityLog.id)).where(SecurityLog.threat_category == "PROMPT_INJECTION")
        jailbreak_stmt = select(func.count(SecurityLog.id)).where(SecurityLog.threat_category == "JAILBREAK")
        pii_stmt = select(func.count(SecurityLog.id)).where(SecurityLog.pii_detected == True)  # noqa: E712

        allowed_count = (await self.session.execute(allowed_stmt)).scalar() or 0
        blocked_count = (await self.session.execute(blocked_stmt)).scalar() or 0
        injection_count = (await self.session.execute(injection_stmt)).scalar() or 0
        jailbreak_count = (await self.session.execute(jailbreak_stmt)).scalar() or 0
        pii_count = (await self.session.execute(pii_stmt)).scalar() or 0

        return {
            "total_requests": total_requests,
            "allowed_requests": allowed_count,
            "blocked_requests": blocked_count,
            "prompt_injection_attempts": injection_count,
            "jailbreak_attempts": jailbreak_count,
            "pii_detection_incidents": pii_count,
            "average_risk_score": avg_risk_score
        }
