"""Health Check route handler for the API v1 layer."""

from __future__ import annotations

import socket
import aiohttp
import aiohttp_jinja2
from aiohttp import web

from src.config.config import Config
from src.config.database import get_engine


def _check_database() -> dict:
    """Synchronously verify the DB connection."""
    try:
        engine = get_engine()
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return {"connected": True}
    except Exception as error:
        return {"connected": False, "error": str(error)}


async def _check_github_token() -> dict:
    """Validate the GitHub token against the GitHub API.

    Hits the /user endpoint which requires authentication.
    Returns the token status, rate-limit info, and the authenticated
    GitHub username when the token is valid.
    """
    token = getattr(Config, "GITHUB_TOKEN", None)

    if not token:
        return {
            "present": False,
            "valid": None,
            "note": "GITHUB_TOKEN not set in .env — Metasploit source will be rate-limited",
        }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VulnRadar/1.0",
    }

    try:
        connector = aiohttp.TCPConnector(family=socket.AF_INET, resolver=aiohttp.ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
            async with session.get(
                "https://api.github.com/user",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                # Rate-limit headers are present on every response
                rate_limit = resp.headers.get("X-RateLimit-Limit")
                rate_remaining = resp.headers.get("X-RateLimit-Remaining")

                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "present": True,
                        "valid": True,
                        "login": data.get("login"),
                        "rate_limit": {
                            "limit": int(rate_limit) if rate_limit else None,
                            "remaining": int(rate_remaining) if rate_remaining else None,
                        },
                    }

                if resp.status == 401:
                    return {
                        "present": True,
                        "valid": False,
                        "error": "Token is invalid or expired — check GITHUB_TOKEN in .env",
                    }

                return {
                    "present": True,
                    "valid": False,
                    "error": f"Unexpected GitHub API response: HTTP {resp.status}",
                }

    except aiohttp.ClientConnectorError:
        return {
            "present": True,
            "valid": None,
            "error": "Could not reach GitHub API — network issue",
        }
    except Exception as exc:
        return {
            "present": True,
            "valid": None,
            "error": f"GitHub token check failed: {exc}",
        }


async def health_check() -> dict:
    """Async health check: DB, NVD API key presence, GitHub token validity."""
    # --- Database ---
    db_status = _check_database()

    # --- NVD API key (presence only — no live call needed) ---
    nvd_key_present = bool(Config.NVD_API_KEY)

    # --- GitHub token (live validation) ---
    github_status = await _check_github_token()

    # --- Aggregate overall status ---
    degraded = (
        not db_status.get("connected")
        or not nvd_key_present
        or github_status.get("valid") is False
    )

    return {
        "status": "degraded" if degraded else "ok",
        "database": db_status,
        "nvd_api_key": {
            "present": nvd_key_present,
            "note": None if nvd_key_present else "NVD_API_KEY not set — limited to 5 req/30s",
        },
        "github_token": github_status,
    }


async def health_endpoint(request: web.Request) -> web.Response:
    """Health check HTTP endpoint."""
    return web.json_response(await health_check())


@aiohttp_jinja2.template("gateway_status.html")
async def get_landing_page_handler(request: web.Request) -> dict:
    """Serve the gateway status dashboard page."""
    return {}
