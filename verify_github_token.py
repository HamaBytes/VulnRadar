import asyncio
import aiohttp

from src.config.config import Config

GITHUB_SECURITY_URL = "https://api.github.com/graphql"

async def test_github_advisory():
    token = getattr(Config, "GITHUB_TOKEN", None)
    print(f"Token present: {bool(token)}")
    if not token:
        print("No token configured!")
        return

    query = """
    query($cve: String!) {
      securityVulnerabilities(first: 1, advisoryTopic: $cve) {
        nodes {
          severity
          summary
          references { url }
          package { name }
        }
      }
    }
    """

    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "VulnRadar/1.0",
        "Content-Type": "application/json",
    }

    # Test with a known CVE that should have GitHub data
    test_cves = ["CVE-2021-44228", "CVE-2023-38408", "CVE-2024-21413"]

    async with aiohttp.ClientSession() as session:
        for cve_id in test_cves:
            print(f"\nTesting {cve_id}...")
            json_payload = {"query": query, "variables": {"cve": cve_id}}
            try:
                async with session.post(
                        GITHUB_SECURITY_URL,
                        headers=headers,
                        json=json_payload,
                        timeout=30
                ) as resp:
                    print(f"  Status: {resp.status}")
                    if resp.status == 200:
                        data = await resp.json()
                        nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
                        if nodes:
                            node = nodes[0]
                            print(f"  Severity: {node.get('severity')}")
                            print(f"  Package: {node.get('package', {}).get('name')}")
                            print(f"  Summary: {node.get('summary', '')[:100]}...")
                        else:
                            print("  No data found")
                    elif resp.status == 401:
                        print("  Invalid token!")
                    elif resp.status == 403:
                        body = await resp.text()
                        if "rate limit" in body.lower():
                            print("  Rate limited!")
                        else:
                            print(f"  Forbidden: {body[:200]}")
                    else:
                        body = await resp.text()
                        print(f"  Error: {body[:200]}")
            except Exception as e:
                print(f"  Exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_github_advisory())
