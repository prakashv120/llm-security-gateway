"""Input Guardrails: Pre-processing and sanitation for inbound requests."""

from app.security.decision_engine import SecurityDecisionEngine, SecurityDecisionResult

class InputGuardrails:
    """Wrapper providing clean input guardrail operations for services."""

    def __init__(self):
        self.decision_engine = SecurityDecisionEngine()

    def process(self, prompt: str) -> SecurityDecisionResult:
        """Run all input inspection steps and return security decision."""
        return self.decision_engine.evaluate(prompt)
