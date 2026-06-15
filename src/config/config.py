from dotenv import load_dotenv
import os
from sqlalchemy.engine import URL

load_dotenv()


class Config:
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_DRIVER = os.getenv("DB_DRIVER", "postgresql+psycopg2")
    NVD_API_KEY = os.getenv("NVD_API_KEY") or os.getenv("NPV_API_KEY")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")          # Optional: raises GitHub API rate-limit

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
