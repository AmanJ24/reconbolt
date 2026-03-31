"""FastAPI application factory.

Usage:
    uvicorn reconbolt.api.app:app --reload
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from reconbolt.config import get_settings


# In-memory store for active scans (production would use Redis/DB)
active_scans: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan — startup/shutdown logic."""
    settings = get_settings()
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    yield
    # Shutdown: cancel any running scans
    for scan_id, task in list(active_scans.items()):
        if isinstance(task, asyncio.Task) and not task.done():
            task.cancel()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="ReconBolt API",
        description="AI-Powered Cybersecurity Reconnaissance Platform",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routes
    from reconbolt.api.routes.health import router as health_router
    from reconbolt.api.routes.scans import router as scans_router

    app.include_router(health_router, tags=["Health"])
    app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])

    return app


# Create the app instance
app = create_app()
