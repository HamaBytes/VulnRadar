import threading
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base

from src.config.config import Config


Base = declarative_base()


class DatabaseConnector:
    """
    Singleton database connector.
    Thread-safe lazy initialization with connection pooling.
    """
    _instance: Optional["DatabaseConnector"] = None
    _lock = threading.Lock()
    _initialized = False

    def __new__(cls) -> "DatabaseConnector":
        if cls._instance is None:
            with cls._lock:
                # Double-check locking
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        # Prevent re-initialization
        if DatabaseConnector._initialized:
            return

        with DatabaseConnector._lock:
            if DatabaseConnector._initialized:
                return

            self._engine: Optional[Engine] = None
            self._session_factory: Optional[sessionmaker] = None
            self._database_url: Optional[str] = None
            DatabaseConnector._initialized = True

    def init(self, database_url: Optional[str] = None, **engine_kwargs) -> "DatabaseConnector":
        """
        Initialize the database connection.
        Idempotent - safe to call multiple times.

        Args:
            database_url: Database URL. If None, uses Config.database_url()
            **engine_kwargs: Additional arguments passed to create_engine()

        Returns:
            self for chaining
        """
        if self._engine is not None:
            return self  # Already initialized

        with DatabaseConnector._lock:
            if self._engine is not None:
                return self  # Double-check after acquiring lock

            self._database_url = database_url or Config.database_url()

            default_kwargs = {
                "pool_pre_ping": True,
                "pool_size": 10,
                "max_overflow": 20,
                "pool_timeout": 30,
                "pool_recycle": 1800,
            }
            default_kwargs.update(engine_kwargs)

            self._engine = create_engine(self._database_url, **default_kwargs)
            self._session_factory = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self._engine
            )

        return self

    @property
    def engine(self) -> Engine:
        """Get the SQLAlchemy engine. Auto-initializes if needed."""
        if self._engine is None:
            self.init()
        return self._engine

    @property
    def session_factory(self) -> sessionmaker:
        """Get the session factory. Auto-initializes if needed."""
        if self._session_factory is None:
            self.init()
        return self._session_factory

    def create_session(self) -> Session:
        """Create a new database session."""
        return self.session_factory()

    def create_all_tables(self) -> None:
        """Create all tables defined in Base metadata."""
        Base.metadata.create_all(bind=self.engine)

    def drop_all_tables(self) -> None:
        """Drop all tables defined in Base metadata."""
        Base.metadata.drop_all(bind=self.engine)

    def close(self) -> None:
        """Dispose the engine and clean up resources."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None

    def __del__(self):
        """Cleanup on garbage collection."""
        self.close()

    def __repr__(self) -> str:
        status = "connected" if self._engine else "not initialized"
        return f"<DatabaseConnector {status}>"


# -----------------------------------------------------------------------------
# Convenience functions and context managers
# -----------------------------------------------------------------------------

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI-style dependency generator.
    Yields a session and handles cleanup.
    """
    db = DatabaseConnector().create_session()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.

    Usage:
        with db_session() as db:
            user = db.query(User).first()
    """
    db = DatabaseConnector().create_session()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def db_session_ro() -> Generator[Session, None, None]:
    """
    Read-only context manager (no auto-commit).

    Usage:
        with db_session_ro() as db:
            users = db.query(User).all()
    """
    db = DatabaseConnector().create_session()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# Module-level convenience accessors
# -----------------------------------------------------------------------------

def init_db(**kwargs) -> DatabaseConnector:
    """Initialize the singleton database connector."""
    return DatabaseConnector().init(**kwargs)


def get_engine() -> Engine:
    """Get the SQLAlchemy engine."""
    return DatabaseConnector().engine


def get_session_factory() -> sessionmaker:
    """Get the session factory."""
    return DatabaseConnector().session_factory
