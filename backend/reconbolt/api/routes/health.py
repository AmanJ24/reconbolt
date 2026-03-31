"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """API health check endpoint."""
    return {"status": "healthy", "service": "reconbolt", "version": "1.0.0"}
