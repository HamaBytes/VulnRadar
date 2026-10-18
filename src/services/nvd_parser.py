from typing import Any

from src.schemas.nvd import NvdApiResponse


def parse_nvd_response(data: dict[str, Any]) -> NvdApiResponse:
    """Parse raw NVD API JSON into validated Pydantic models."""
    return NvdApiResponse.model_validate(data)


def extract_best_cvss(cve: NvdApiResponse) -> tuple[float | None, str | None, str | None]:
    """Get the best CVSS score from parsed NVD data."""
    # This operates on the first vulnerability if passed a full response
    if not cve.vulnerabilities:
        return None, None, None
    return cve.vulnerabilities[0].cve.best_score()