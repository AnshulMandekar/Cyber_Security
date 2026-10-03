"""FastAPI application factory.

Run from the project root with::

    uvicorn oktatrace.api.app:app --app-dir backend --reload
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from oktatrace import DISCLAIMER, __version__
from oktatrace.api.detection_routes import router as detection_router
from oktatrace.api.har_routes import router as har_router
from oktatrace.api.log_routes import router as log_router
from oktatrace.api.report_routes import router as report_router
from oktatrace.api.timeline_routes import router as timeline_router
from oktatrace.config import get_settings


def create_app() -> FastAPI:
    """Build the API with CORS for the dashboard dev server."""
    app = FastAPI(title="OktaTrace API", version=__version__, description=DISCLAIMER)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(get_settings().cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition", "X-OktaTrace-Redactions"],
    )

    @app.get("/api/health", tags=["meta"])
    def health() -> dict[str, object]:
        """Liveness check that also carries the synthetic-data disclaimer."""
        return {"status": "ok", "version": __version__, "synthetic_data_only": True,
                "disclaimer": DISCLAIMER}

    app.include_router(har_router)
    app.include_router(log_router)
    app.include_router(detection_router)
    app.include_router(timeline_router)
    app.include_router(report_router)
    return app


app = create_app()
