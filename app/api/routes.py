"""REST API routes for the LLM Security Gateway."""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.config.settings import settings
from app.database.connection import get_db_session
from app.database.repository import SecurityRepository
from app.llm.ollama_client import OllamaClient
from app.schemas.request import ChatRequest, DetectRequest
from app.schemas.response import (
    ChatResponse,
    DetectResponse,
    SecurityLogItem,
    SecurityLogsResponse,
    SecurityStatsResponse,
    HealthResponse,
)
from app.services.chat_service import ChatService
from app.services.security_service import SecurityService

router = APIRouter(prefix="/api", tags=["Security Gateway"])


@router.post(
    "/chat",
    response_model=ChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit prompt to LLM through AI Guardrails",
    description="Inspects user prompt for injection, jailbreak, and PII threats. If safe, forwards sanitized prompt to Ollama LLM, runs output guardrails, records security logs in PostgreSQL, and returns the verified response."
)
async def chat_endpoint(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db_session)
) -> ChatResponse:
    """Secure chat endpoint."""
    service = ChatService(db_session=db)
    return await service.process_chat(request)


@router.post(
    "/detect",
    response_model=DetectResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze prompt for security threats without LLM invocation",
    description="Evaluates an input string against prompt injection heuristics, jailbreak indicators, and PII patterns, returning risk metrics, matched threat categories, and recommended actions."
)
async def detect_endpoint(
    request: DetectRequest,
    db: AsyncSession = Depends(get_db_session)
) -> DetectResponse:
    """Threat detection inspection endpoint."""
    service = SecurityService(db_session=db)
    return await service.detect_threats(request.prompt)


@router.get(
    "/security/logs",
    response_model=SecurityLogsResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve security audit logs",
    description="Fetch paginated audit logs containing threat categories, risk scores, decisions, and sanitized metadata."
)
async def get_logs_endpoint(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=200, description="Maximum records to return"),
    decision: Optional[str] = Query(None, description="Filter by decision: ALLOW, BLOCK, MASK, REVIEW"),
    threat_category: Optional[str] = Query(None, description="Filter by threat category"),
    db: AsyncSession = Depends(get_db_session)
) -> SecurityLogsResponse:
    """Security logs retrieval endpoint."""
    repository = SecurityRepository(db)
    records = await repository.get_logs(
        skip=skip,
        limit=limit,
        decision=decision,
        threat_category=threat_category
    )
    items = [SecurityLogItem(**record.to_dict()) for record in records]
    return SecurityLogsResponse(total_returned=len(items), logs=items)


@router.get(
    "/security/stats",
    response_model=SecurityStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve aggregate security statistics",
    description="Aggregates metrics including total requests, allowed/blocked counts, injection attempts, jailbreaks, PII detections, and average risk score."
)
async def get_stats_endpoint(
    db: AsyncSession = Depends(get_db_session)
) -> SecurityStatsResponse:
    """Security statistics endpoint."""
    repository = SecurityRepository(db)
    stats_dict = await repository.get_stats()
    return SecurityStatsResponse(**stats_dict)


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Check gateway and subsystem health",
    description="Verifies connectivity to the PostgreSQL database and local Ollama LLM service."
)
async def health_endpoint(
    db: AsyncSession = Depends(get_db_session)
) -> HealthResponse:
    """Health status endpoint."""
    # Check Database Connectivity
    db_status = {"status": "connected"}
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = {"status": "disconnected", "error": str(e)}

    # Check Ollama Connectivity
    ollama_client = OllamaClient()
    ollama_health = await ollama_client.check_health()

    overall_status = "healthy"
    if db_status.get("status") != "connected" or ollama_health.get("status") != "connected":
        overall_status = "degraded"

    return HealthResponse(
        status=overall_status,
        version=settings.APP_VERSION,
        database=db_status,
        llm_service=ollama_health
    )
