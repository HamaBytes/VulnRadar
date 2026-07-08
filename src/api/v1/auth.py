# src/api/v1/auth.py
from aiohttp import web
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from src.config.database import DatabaseConnector, init_db
from src.models.users import User
from src.services.security import hash_password, verify_password, create_jwt_token, verify_jwt_token
from src.services.logger import Logger  # Adjust import path to match your project

routes = web.RouteTableDef()
logger = Logger(name="api_auth", level="INFO", console_output=True)



def _get_db_session():
    """Get database session, initializing if needed."""
    connector = DatabaseConnector()
    connector.init()
    return connector.create_session()

@routes.post("/api/v1/auth/register")
async def register_user(request):
    request_id = id(request)
    logger.info(f"[{request_id}] Registration attempt received")

    try:
        # Parse and validate request body
        try:
            data = await request.json()
        except Exception:
            logger.warning(f"[{request_id}] Invalid JSON in request body")
            return web.json_response(
                {"error": "Invalid JSON in request body"},
                status=400
            )

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        logger.debug(f"[{request_id}] Validating email: {email}")

        # Email validation
        if not email:
            logger.warning(f"[{request_id}] Registration failed: email is empty")
            return web.json_response(
                {"error": "Email is required"},
                status=400
            )

        if "@" not in email or "." not in email.split("@")[-1]:
            logger.warning(f"[{request_id}] Registration failed: invalid email format: {email}")
            return web.json_response(
                {"error": "Valid email required (e.g., user@domain.com)"},
                status=400
            )

        # Password validation
        if not password:
            logger.warning(f"[{request_id}] Registration failed: password is empty")
            return web.json_response(
                {"error": "Password is required"},
                status=400
            )

        if len(password) < 8:
            logger.warning(f"[{request_id}] Registration failed: password too short ({len(password)} chars)")
            return web.json_response(
                {"error": "Password must be at least 8 characters"},
                status=400
            )

        # Database operations
        db = _get_db_session()
        try:
            logger.debug(f"[{request_id}] Checking for existing user: {email}")
            existing = db.execute(
                select(User).where(User.email == email)
            ).scalar_one_or_none()

            if existing is not None:
                logger.warning(f"[{request_id}] Registration failed: user already exists: {email}")
                return web.json_response(
                    {"error": "User already exists"},
                    status=409
                )

            logger.info(f"[{request_id}] Creating new user: {email}")
            new_user = User(
                email=email,
                password_hash=hash_password(password)
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            token = create_jwt_token(new_user.id, new_user.email)
            print(token)
            logger.info(f"[{request_id}] User registered successfully: id={new_user.id}, email={email}")
            return web.json_response({
                "token": token,
                "user": {
                    "id": new_user.id,
                    "email": new_user.email
                }
            }, status=201)

        except IntegrityError as e:
            db.rollback()
            logger.error(f"[{request_id}] Database integrity error during registration: {e}")
            return web.json_response(
                {"error": "Registration failed due to data conflict"},
                status=409
            )
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"[{request_id}] Database error during registration: {e}")
            return web.json_response(
                {"error": "Database error occurred"},
                status=500
            )
        finally:
            db.close()

    except Exception as e:
        logger.critical(f"[{request_id}] Unexpected error during registration: {e}")
        return web.json_response(
            {"error": "Internal server error"},
            status=500
        )


@routes.post("/api/v1/auth/login")
async def login_user(request):
    request_id = id(request)
    logger.info(f"[{request_id}] Login attempt received")

    try:
        # Parse request body
        try:
            data = await request.json()
        except Exception:
            logger.warning(f"[{request_id}] Invalid JSON in request body")
            return web.json_response(
                {"error": "Invalid JSON in request body"},
                status=400
            )

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        logger.debug(f"[{request_id}] Login attempt for: {email}")

        # Validation
        if not email or not password:
            logger.warning(f"[{request_id}] Login failed: missing credentials")
            return web.json_response(
                {"error": "Email and password are required"},
                status=400
            )

        # Database lookup
        db = _get_db_session()
        try:
            user = db.execute(
                select(User).where(User.email == email)
            ).scalar_one_or_none()

            # Verify credentials (constant-time comparison to prevent timing attacks)
            if user is None:
                logger.warning(f"[{request_id}] Login failed: user not found: {email}")
                return web.json_response(
                    {"error": "Invalid email or password"},
                    status=401
                )

            if not verify_password(password, user.password_hash):
                logger.warning(f"[{request_id}] Login failed: invalid password for: {email}")
                return web.json_response(
                    {"error": "Invalid email or password"},
                    status=401
                )

            token = create_jwt_token(user.id, user.email)

            logger.info(f"[{request_id}] Login successful: id={user.id}, email={email}")
            return web.json_response({
                "token": token,
                "user": {
                    "id": user.id,
                    "email": user.email
                }
            })

        except SQLAlchemyError as e:
            logger.error(f"[{request_id}] Database error during login: {e}")
            return web.json_response(
                {"error": "Database error occurred"},
                status=500
            )
        finally:
            db.close()

    except Exception as e:
        logger.critical(f"[{request_id}] Unexpected error during login: {e}")
        return web.json_response(
            {"error": "Internal server error"},
            status=500
        )


@routes.get("/api/v1/auth/me")
async def get_current_user(request):
    request_id = id(request)
    logger.info(f"[{request_id}] Token validation request")

    try:
        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            logger.warning(f"[{request_id}] Token validation failed: no Authorization header")
            return web.json_response(
                {"error": "Authorization header is required"},
                status=401
            )

        if not auth_header.startswith("Bearer "):
            logger.warning(f"[{request_id}] Token validation failed: invalid header format")
            return web.json_response(
                {"error": "Authorization header must start with 'Bearer '"},
                status=401
            )

        token = auth_header[7:]  # Remove "Bearer "

        if not token:
            logger.warning(f"[{request_id}] Token validation failed: empty token")
            return web.json_response(
                {"error": "Token is empty"},
                status=401
            )

        logger.debug(f"[{request_id}] Verifying token...")
        payload = verify_jwt_token(token)

        logger.info(f"[{request_id}] Token validated: user_id={payload.get('sub')}")
        return web.json_response({
            "user": {
                "id": int(payload["sub"]),
                "email": payload.get("email", "")
            }
        })

    except ValueError as e:
        error_msg = str(e).lower()
        if "expired" in error_msg:
            logger.warning(f"[{request_id}] Token validation failed: token expired")
            return web.json_response(
                {"error": "Token has expired, please log in again"},
                status=401
            )
        logger.warning(f"[{request_id}] Token validation failed: {e}")
        return web.json_response(
            {"error": "Invalid token"},
            status=401
        )
    except Exception as e:
        logger.critical(f"[{request_id}] Unexpected error during token validation: {e}")
        return web.json_response(
            {"error": "Internal server error"},
            status=500
        )


auth_routes = routes