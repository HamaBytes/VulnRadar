# src/config/config.py
from dotenv import load_dotenv
import os
from sqlalchemy.engine import URL

load_dotenv()


class Config:
    # Database
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_DRIVER = os.getenv("DB_DRIVER", "postgresql+psycopg2")

    # API Keys
    NVD_API_KEY = os.getenv("NVD_API_KEY") or os.getenv("NPV_API_KEY")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

    # JWT Auth
    JWT_SECRET = os.getenv("JWT_SECRET")
    JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

    @classmethod
    def database_url(cls) -> str:
        explicit_url = os.getenv("DATABASE_URL")
        if explicit_url:
            return explicit_url

        if not all([cls.DB_USER, cls.DB_PASSWORD, cls.DB_NAME]):
            raise ValueError("Database credentials are not fully configured.")

        return (
            URL.create(
                drivername=cls.DB_DRIVER,
                username=cls.DB_USER,
                password=cls.DB_PASSWORD,
                host=cls.DB_HOST,
                port=int(cls.DB_PORT) if cls.DB_PORT else None,
                database=cls.DB_NAME,
            )
            .render_as_string(hide_password=False)
        )

    @classmethod
    def validate_jwt_secret(cls) -> None:
        """Ensure JWT_SECRET is set and sufficiently long."""
        if not cls.JWT_SECRET:
            raise ValueError("JWT_SECRET environment variable is required.")
        if len(cls.JWT_SECRET) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters long.")


# Validate on import (fail fast)
Config.validate_jwt_secret()