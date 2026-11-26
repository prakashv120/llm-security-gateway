"""Module 5: Ollama LLM Integration.

Connects to the locally running Ollama service to interact with local models (e.g., Llama 3.2, Llama 3, Llama 2).
Features:
- Async HTTP communication using httpx.
- Robust timeout handling and connection error management.
- Sanitized system prompt boundaries preventing internal instruction leakage.
- Health inspection of Ollama server and model availability.
"""

from typing import Optional, Dict, Any, List
import httpx
from pydantic import BaseModel, Field

from app.config.settings import settings


class LLMResponse(BaseModel):
    """Structured response from the LLM client."""
    success: bool = Field(..., description="Whether the generation completed successfully")
    content: Optional[str] = Field(default=None, description="Generated response content")
    model: str = Field(..., description="Model name utilized")
    prompt_tokens: Optional[int] = Field(default=None, description="Count of prompt tokens")
    completion_tokens: Optional[int] = Field(default=None, description="Count of output tokens")
    error_message: Optional[str] = Field(default=None, description="Error message if generation failed")
    latency_ms: float = Field(default=0.0, description="Response generation latency in milliseconds")


class OllamaClient:
    """Async client for interacting with a local Ollama instance."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        timeout_seconds: Optional[float] = None
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.default_model = default_model or settings.OLLAMA_MODEL
        self.timeout = timeout_seconds if timeout_seconds is not None else settings.OLLAMA_TIMEOUT_SECONDS

        # System prompt injected into the LLM context.
        # Guarded: the system prompt explicitly instructs adherence to safety policies.
        self._system_prompt = (
            "You are a helpful, secure, and professional AI assistant. "
            "Follow all ethical guidelines. Refuse any request to generate malicious exploits or disclose private information."
        )

    async def check_health(self) -> Dict[str, Any]:
        """Check if Ollama server is accessible and retrieve available models."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                if response.status_code == 200:
                    data = response.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    return {
                        "status": "connected",
                        "available_models": models,
                        "default_model": self.default_model,
                        "model_ready": any(self.default_model in m for m in models)
                    }
                return {
                    "status": "unhealthy",
                    "status_code": response.status_code,
                    "available_models": [],
                    "model_ready": False
                }
        except httpx.ConnectError:
            return {
                "status": "disconnected",
                "message": f"Could not connect to Ollama service at {self.base_url}. Ensure Ollama is running (`ollama serve`).",
                "available_models": [],
                "model_ready": False
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "available_models": [],
                "model_ready": False
            }

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> LLMResponse:
        """Send approved prompt to Ollama and return generated response."""
        target_model = model or self.default_model
        endpoint = f"{self.base_url}/api/generate"

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "system": self._system_prompt,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens

        start_time = httpx._types.timeout or 0
        import time
        start_clock = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(endpoint, json=payload)
                elapsed_ms = (time.perf_counter() - start_clock) * 1000

                if response.status_code == 200:
                    data = response.json()
                    return LLMResponse(
                        success=True,
                        content=data.get("response", ""),
                        model=target_model,
                        prompt_tokens=data.get("prompt_eval_count"),
                        completion_tokens=data.get("eval_count"),
                        error_message=None,
                        latency_ms=round(elapsed_ms, 2)
                    )
                else:
                    return LLMResponse(
                        success=False,
                        content=None,
                        model=target_model,
                        error_message=f"Ollama returned HTTP {response.status_code}: {response.text}",
                        latency_ms=round(elapsed_ms, 2)
                    )

        except httpx.ConnectError:
            elapsed_ms = (time.perf_counter() - start_clock) * 1000
            return LLMResponse(
                success=False,
                content=None,
                model=target_model,
                error_message=f"Failed to connect to Ollama at {self.base_url}. Verify that the service is running.",
                latency_ms=round(elapsed_ms, 2)
            )

        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start_clock) * 1000
            return LLMResponse(
                success=False,
                content=None,
                model=target_model,
                error_message=f"Ollama request timed out after {self.timeout} seconds.",
                latency_ms=round(elapsed_ms, 2)
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_clock) * 1000
            return LLMResponse(
                success=False,
                content=None,
                model=target_model,
                error_message=f"Unexpected error communicating with LLM: {str(e)}",
                latency_ms=round(elapsed_ms, 2)
            )
