"""Chat service: orchestrates full pipeline from input guardrails to LLM and output validation."""

import time
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.database.repository import SecurityRepository
from app.llm.ollama_client import OllamaClient
from app.schemas.request import ChatRequest
from app.schemas.response import ChatResponse
from app.security.decision_engine import SecurityDecision, SecurityDecisionEngine
from app.security.output_guardrails import OutputGuardrails


class ChatService:
    """End-to-end chat orchestration implementing defense-in-depth."""

    def __init__(
        self,
        db_session: Optional[AsyncSession] = None,
        ollama_client: Optional[OllamaClient] = None
    ):
        self.db_session = db_session
        self.decision_engine = SecurityDecisionEngine()
        self.output_guardrails = OutputGuardrails()
        self.llm_client = ollama_client or OllamaClient()

    async def process_chat(self, request: ChatRequest) -> ChatResponse:
        """Execute the multi-stage security gateway pipeline."""
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())
        model_name = request.model or settings.OLLAMA_MODEL

        # Stage 1: Input Guardrails & Threat Evaluation
        decision_result = self.decision_engine.evaluate(request.prompt)

        # Stage 2: Handle Blocked or Review-Flagged Requests
        if decision_result.decision == SecurityDecision.BLOCK:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.db_session:
                repo = SecurityRepository(self.db_session)
                await repo.create_log(
                    request_id=request_id,
                    threat_category=decision_result.primary_threat.value,
                    risk_score=decision_result.overall_risk_score,
                    security_decision=decision_result.decision.value,
                    pii_detected=decision_result.pii_result.has_pii,
                    pii_types=decision_result.pii_result.detected_types,
                    prompt_summary=decision_result.sanitized_prompt,
                    reasons=decision_result.reasons,
                    processing_status="BLOCKED_INPUT",
                    model_used=model_name,
                    latency_ms=round(elapsed_ms, 2)
                )

            return ChatResponse(
                request_id=request_id,
                decision=decision_result.decision.value,
                risk_score=decision_result.overall_risk_score,
                threat_detected=True,
                threat_category=decision_result.primary_threat.value,
                response="[SECURITY GATEWAY ERROR: Request blocked due to security policy violations.]",
                pii_masked=decision_result.pii_result.has_pii,
                reasons=decision_result.reasons,
                execution_time_ms=round(elapsed_ms, 2)
            )

        if decision_result.decision == SecurityDecision.REVIEW:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.db_session:
                repo = SecurityRepository(self.db_session)
                await repo.create_log(
                    request_id=request_id,
                    threat_category=decision_result.primary_threat.value,
                    risk_score=decision_result.overall_risk_score,
                    security_decision=decision_result.decision.value,
                    pii_detected=decision_result.pii_result.has_pii,
                    pii_types=decision_result.pii_result.detected_types,
                    prompt_summary=decision_result.sanitized_prompt,
                    reasons=decision_result.reasons,
                    processing_status="FLAGGED_FOR_REVIEW",
                    model_used=model_name,
                    latency_ms=round(elapsed_ms, 2)
                )

            return ChatResponse(
                request_id=request_id,
                decision=decision_result.decision.value,
                risk_score=decision_result.overall_risk_score,
                threat_detected=True,
                threat_category=decision_result.primary_threat.value,
                response="[SECURITY GATEWAY NOTICE: Request flagged for security review. Prompt execution paused.]",
                pii_masked=decision_result.pii_result.has_pii,
                reasons=decision_result.reasons,
                execution_time_ms=round(elapsed_ms, 2)
            )

        # Stage 3: Forward Approved Prompt (with PII Masked) to Ollama LLM
        forwarded_prompt = decision_result.sanitized_prompt
        llm_response = await self.llm_client.generate(
            prompt=forwarded_prompt,
            model=model_name,
            temperature=request.temperature or 0.7,
            max_tokens=request.max_tokens
        )

        # Stage 4: Handle LLM Execution Errors (Timeouts, Disconnects)
        if not llm_response.success:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.db_session:
                repo = SecurityRepository(self.db_session)
                await repo.create_log(
                    request_id=request_id,
                    threat_category=decision_result.primary_threat.value,
                    risk_score=decision_result.overall_risk_score,
                    security_decision=decision_result.decision.value,
                    pii_detected=decision_result.pii_result.has_pii,
                    pii_types=decision_result.pii_result.detected_types,
                    prompt_summary=decision_result.sanitized_prompt,
                    reasons=decision_result.reasons + [f"LLM Error: {llm_response.error_message}"],
                    processing_status="LLM_ERROR",
                    model_used=model_name,
                    latency_ms=round(elapsed_ms, 2)
                )

            return ChatResponse(
                request_id=request_id,
                decision=decision_result.decision.value,
                risk_score=decision_result.overall_risk_score,
                threat_detected=decision_result.threat_detected,
                threat_category=decision_result.primary_threat.value,
                response=f"[GATEWAY ERROR: LLM execution failed: {llm_response.error_message}]",
                pii_masked=decision_result.pii_result.has_pii,
                reasons=decision_result.reasons + [llm_response.error_message or "Unknown LLM error"],
                execution_time_ms=round(elapsed_ms, 2)
            )

        # Stage 5: Output Guardrails Validation
        final_output = llm_response.content or ""
        reasons = list(decision_result.reasons)
        processing_status = "SUCCESS"

        if settings.ENABLE_OUTPUT_GUARDRAILS:
            output_result = self.output_guardrails.validate(final_output)
            final_output = output_result.sanitized_output

            if not output_result.is_safe:
                processing_status = "BLOCKED_OUTPUT"
                reasons.extend(output_result.violations)
            elif output_result.violations:
                reasons.extend(output_result.violations)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Stage 6: Database Security Record Persistence
        if self.db_session:
            repo = SecurityRepository(self.db_session)
            await repo.create_log(
                request_id=request_id,
                threat_category=decision_result.primary_threat.value,
                risk_score=decision_result.overall_risk_score,
                security_decision=decision_result.decision.value,
                pii_detected=decision_result.pii_result.has_pii,
                pii_types=decision_result.pii_result.detected_types,
                prompt_summary=decision_result.sanitized_prompt,
                reasons=reasons,
                processing_status=processing_status,
                model_used=model_name,
                latency_ms=round(elapsed_ms, 2)
            )

        return ChatResponse(
            request_id=request_id,
            decision=decision_result.decision.value,
            risk_score=decision_result.overall_risk_score,
            threat_detected=decision_result.threat_detected,
            threat_category=decision_result.primary_threat.value,
            response=final_output,
            pii_masked=decision_result.pii_result.has_pii,
            reasons=reasons,
            execution_time_ms=round(elapsed_ms, 2)
        )
