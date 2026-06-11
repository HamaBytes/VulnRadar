    """NVD fetch service."""

    from __future__ import annotations

    import json
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen

    from src.models.nvd import NvdApiResponse
    from src.services.config import Config

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


    def fetch_vulnerabilities(query: str, results_per_page: int = 20) -> NvdApiResponse:
        params = {"keywordSearch": query, "resultsPerPage": results_per_page}
        request_url = f"{NVD_API_URL}?{urlencode(params)}"
        headers = {"User-Agent": "VulnRadar/1.0"}

        if Config.NVD_API_KEY:
            headers["apiKey"] = Config.NVD_API_KEY

        request = Request(request_url, headers=headers)

        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))

        return NvdApiResponse.from_dict(payload)
