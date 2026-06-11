import os

from aiohttp import web

from src.api.routes import health_endpoint


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/health", health_endpoint)
    return app


if __name__ == '__main__':
    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "8000"))
    web.run_app(create_app(), host=host, port=port)
