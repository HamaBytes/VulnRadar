from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from src.config.database import DatabaseConnector, init_db
from src.models.users import User
from src.services.logger import Logger
from src.services.security import hash_password, verify_password
logger = Logger(name="user_repositorie", level="INFO", console_output=True)
def _get_db_session():
    """Get database session, initializing if needed."""
    connector = DatabaseConnector()
    connector.init()
    return connector.create_session()


class UserAlreadyExistsError(Exception):
    """Raised when attempting to register an email that's already taken."""


def create_user(email: str, password: str) -> User:
    db = _get_db_session()
    try:
        logger.debug(f"Checking for existing user: {email}")
        existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

        if existing is not None:
            logger.warning(f"Registration failed: user already exists: {email}")
            raise UserAlreadyExistsError(f"User already exists: {email}")

        logger.info(f"Creating new user: {email}")
        new_user = User(email=email, password_hash=hash_password(password))
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except IntegrityError:
        db.rollback()
        raise
    except SQLAlchemyError:
        db.rollback()
        raise
    finally:
        db.close()
def authenticate_user(email: str, password: str) -> User | None:
    """Returns the User if credentials are valid, otherwise None."""
    db = _get_db_session()
    try:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user
    finally:
        db.close()