from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.services.config import Config

DATABASE_URL = None
engine = None
SessionLocal = None


def init_db():
    global DATABASE_URL, engine, SessionLocal

    DATABASE_URL = Config.database_url()
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine


def get_db():
    if SessionLocal is None:
        init_db()

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
