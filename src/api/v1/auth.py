from aiohttp import web
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.services.logger import Logger
from src.services.security import create_jwt_token, verify_jwt_token
from services.users import UserAlreadyExistsError, authenticate_user, create_user

routes = web.RouteTableDef()
logger = Logger(name="api_auth", level="INFO", console_output=True)


@routes.post("/api/v1/auth/register")
async def register_user(request):
    request_id = id(request)
    logger.info(f"[{request_id}] Registration attempt received")

    try:
        try:
            data = await request.json()
        except Exception:
            logger.warning(f"[{request_id}] Invalid JSON in request body")
            return web.json_response(
                {"error": "Invalid JSON in request body"},
                status=400
            )

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if not email or not password:
            logger.warning(f"[{request_id}] Registration failed: missing email or password")
            return web.json_response(
                {"error": "Email and password are required"},
                status=400
            )

        if len(password) < 8:
            logger.warning(f"[{request_id}] Registration failed: password too short")
            return web.json_response(
                {"error": "Password must be at least 8 characters"},
                status=400
            )

        try:
            new_user = create_user(email, password)
        except UserAlreadyExistsError:
            logger.warning(f"[{request_id}] Registration failed: user already exists: {email}")
            return web.json_response(
                {"error": "User already exists"},
                status=409
            )
        except IntegrityError as e:
            logger.error(f"[{request_id}] Database integrity error during registration: {e}")
            return web.json_response(
                {"error": "Registration failed due to data conflict"},
                status=409
            )
        except SQLAlchemyError as e:
            logger.error(f"[{request_id}] Database error during registration: {e}")
            return web.json_response(
                {"error": "Database error occurred"},
                status=500
            )

        token = create_jwt_token(new_user.id, new_user.email)
        logger.info(f"[{request_id}] User registered successfully: id={new_user.id}, email={email}")
        return web.json_response({
            "token": token,
            "user": {
                "id": new_user.id,
                "email": new_user.email
            }
        }, status=201)

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
        try:
            data = await request.json()
        except Exception:
            logger.warning(f"[{request_id}] Invalid JSON in request body")
            return web.json_response(
                {"error": "Invalid JSON in request body"},
                status=400
            )

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        logger.debug(f"[{request_id}] Login attempt for: {email}")

        if not email or not password:
            logger.warning(f"[{request_id}] Login failed: missing credentials")
            return web.json_response(
                {"error": "Email and password are required"},
                status=400
            )

        try:
            user = authenticate_user(email, password)
        except SQLAlchemyError as e:
            logger.error(f"[{request_id}] Database error during login: {e}")
            return web.json_response(
                {"error": "Database error occurred"},
                status=500
            )

        if user is None:
            logger.warning(f"[{request_id}] Login failed: invalid credentials for {email}")
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