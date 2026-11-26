"""Request validation schemas."""

from typing import Optional
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    """Payload for submitting a prompt to the secure chat pipeline."""
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="User prompt text to evaluate and send to the LLM"
    )
    model: Optional[str] = Field(
        default=None,
        description="Optional override for the local Ollama model name (e.g. llama3.2)"
    )
    temperature: Optional[float] = Field(
        default=0.7,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for text generation"
    )
    max_tokens: Optional[int] = Field(
        default=None,
        ge=1,
        le=8192,
        description="Maximum generation token budget"
    )


class DetectRequest(BaseModel):
    """Payload for analyzing a prompt for threats without calling the LLM."""
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Prompt to analyze for security vulnerabilities and PII"
    )
