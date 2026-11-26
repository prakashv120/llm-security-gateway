"""FastAPI application entrypoint for the LLM Security Gateway."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as api_router
from app.config.settings import settings
from app.database.connection import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for startup and shutdown routines."""
    # Startup: Initialize database schema
    try:
        await init_db()
    except Exception as e:
        print(f"[WARNING] Database initialization deferred or failed: {e}")
    yield
    # Shutdown routines can be added here


# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Production AI Guardrails & Threat Detection Gateway sitting between users and LLMs. "
        "Protects against prompt injections, jailbreaks, and PII leakage while validating LLM responses."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure internal errors do not leak stack traces or internal secrets to users."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Gateway Error",
            "message": "An unexpected error occurred during request processing. Please try again later.",
            "type": exc.__class__.__name__
        }
    )

# Include API Router
app.include_router(api_router)


@app.get("/", tags=["Root"])
async def root():
    """Root info endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "active",
        "docs": "/docs"
    }
