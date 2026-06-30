# src/api/middleware/auth.py
from aiohttp import web
from src.services.security import verify_jwt_token

@web.middleware
async def auth_middleware(request, handler):
    # Public paths that don't require auth
    public_paths = {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/health",
        "/",
    }

    if request.path in public_paths or request.path.startswith("/static"):
        return await handler(request)

    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return web.json_response({"error": "Missing authorization header"}, status=401)

    token = auth_header[7:]

    try:
        payload = verify_jwt_token(token)
        request["user"] = {
            "id": int(payload["sub"]),
            "email": payload["email"]
        }
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=401)

    return await handler(request)


def require_auth(func):
    """Decorator for handlers that require authentication."""
    async def wrapper(request):
        if "user" not in request:
            return web.json_response({"error": "Authentication required"}, status=401)
        return await func(request)
    return wrapper