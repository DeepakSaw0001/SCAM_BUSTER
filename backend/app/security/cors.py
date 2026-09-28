from fastapi.middleware.cors import CORSMiddleware
from app.config.settings import settings


def setup_cors(app):
    """Configure CORS middleware securely to support local development and cloud deployments."""
    origins = list(settings.CORS_ORIGINS or [])

    # If wildcard is configured, use allow_origin_regex so credentials can still be True
    if "*" in origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[],
            allow_origin_regex=r"^https?://.*",
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            allow_headers=["*"],
            expose_headers=["*"],
        )
    else:
        # Allow configured origins PLUS regex pattern for common frontend cloud providers (Vercel, Netlify, Render)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_origin_regex=r"^https?://([a-zA-Z0-9-]+\.)*(vercel\.app|netlify\.app|onrender\.com)(:[0-9]+)?$",
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            allow_headers=["*"],
            expose_headers=["*"],
        )
