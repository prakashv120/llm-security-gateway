"""Response validation schemas."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ChatResponse(BaseModel):
    """Response returned by the /api/chat endpoint."""
    request_id: str = Field(..., description="Unique UUID tracking this request")
    decision: str = Field(..., description="Security decision: ALLOW, MASK, REVIEW, or BLOCK")
    risk_score: float = Field(..., description="Aggregated risk score between 0.0 and 1.0")
    threat_detected: bool = Field(..., description="Whether an injection, jailbreak, or PII was identified")
    threat_category: str = Field(..., description="Identified threat category")
    response: Optional[str] = Field(None, description="Validated LLM response text, or null if blocked")
    pii_masked: bool = Field(..., description="Whether sensitive PII was masked before forwarding")
    reasons: List[str] = Field(default_factory=list, description="Security explanations or policy flags")
    execution_time_ms: float = Field(..., description="Total pipeline latency in milliseconds")


class DetectResponse(BaseModel):
    """Response returned by the /api/detect endpoint."""
    request_id: str = Field(..., description="Unique UUID tracking this inspection")
    threat_detected: bool = Field(..., description="True if any security threat was found")
    threat_category: str = Field(..., description="Primary threat category")
    risk_score: float = Field(..., description="Assessed risk score from 0.0 to 1.0")
    decision: str = Field(..., description="Recommended gateway action: ALLOW, MASK, REVIEW, or BLOCK")
    pii_detected: bool = Field(..., description="Whether sensitive PII was detected")
    pii_types: List[str] = Field(default_factory=list, description="Types of PII found in prompt")
    masked_prompt: Optional[str] = Field(None, description="Sanitized version of prompt with PII redacted")
    reasons: List[str] = Field(default_factory=list, description="Matched patterns and security observations")


class SecurityLogItem(BaseModel):
    """Single security log entry representation."""
    id: str
    request_id: str
    timestamp: Optional[str]
    threat_category: str
    risk_score: float
    security_decision: str
    pii_detected: bool
    pii_types: List[str]
    prompt_summary: Optional[str]
    reasons: List[str]
    processing_status: str
    model_used: Optional[str]
    latency_ms: float


class SecurityLogsResponse(BaseModel):
    """Paginated list of security logs."""
    total_returned: int
    logs: List[SecurityLogItem]


class SecurityStatsResponse(BaseModel):
    """Aggregated security metrics across gateway transactions."""
    total_requests: int = Field(..., description="Total number of requests received")
    allowed_requests: int = Field(..., description="Total requests permitted through to LLM")
    blocked_requests: int = Field(..., description="Total requests rejected by guardrails")
    prompt_injection_attempts: int = Field(..., description="Total prompt injection threats intercepted")
    jailbreak_attempts: int = Field(..., description="Total jailbreak attempts intercepted")
    pii_detection_incidents: int = Field(..., description="Total requests where PII was identified")
    average_risk_score: float = Field(..., description="Mean risk score across all requests")


class HealthResponse(BaseModel):
    """Gateway health check status."""
    status: str = Field(..., description="Overall gateway operational status")
    version: str = Field(..., description="Software version")
    database: Dict[str, Any] = Field(..., description="PostgreSQL database connectivity status")
    llm_service: Dict[str, Any] = Field(..., description="Ollama service and model status")
