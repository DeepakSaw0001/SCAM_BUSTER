from typing import List, Any
from pydantic import Field, AliasChoices, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings validated by Pydantic."""
    APP_ENV: str = "development"
    PROJECT_NAME: str = "scambuster-api"
    API_V1_PREFIX: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = Field(
        default="mongodb://localhost:27017",
        validation_alias=AliasChoices("DATABASE_URL", "MONGODB_URI", "MONGO_URI")
    )
    DATABASE_NAME: str = "scambuster"

    # Security & CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5000",
    ]
    JWT_SECRET: str = "scambuster-super-secret-jwt-key-32-chars-2026"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    GEMINI_API_KEY: str = "AQ.Ab8RN6J4-KjiJL5PiTEHk8YlEl081T-KHS2SPy_IiVzZXDf9VQ"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            v_stripped = v.strip()
            if not v_stripped or v_stripped == "*":
                return ["*"]
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    import json
                    return json.loads(v_stripped)
                except Exception:
                    pass
            return [x.strip() for x in v_stripped.split(",") if x.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(x) for x in v]
        return v

    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
