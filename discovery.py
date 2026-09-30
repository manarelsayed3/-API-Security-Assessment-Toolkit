import requests
from urllib.parse import urljoin

from scanner.findings import Finding


COMMON_ENDPOINTS = [
    "/api",
    "/api/users",
    "/api/users/1",
    "/api/v1",
    "/api/v1/users",
    "/api/v1/users/1",
    "/swagger.json",
    "/openapi.json",
]


def discover_endpoints(base_url):
    findings = []

    base_url = base_url.rstrip("/") + "/"

    for endpoint in COMMON_ENDPOINTS:

        url = urljoin(
            base_url,
            endpoint.lstrip("/")
        )

        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False
            )

            if response.status_code != 404:

                findings.append(
                    Finding(
                        severity="INFO",
                        title="Endpoint Discovered",
                        category="Discovery",
                        endpoint=url,
                        evidence=(
                            f"{url} returned HTTP "
                            f"{response.status_code}."
                        ),
                        recommendation=(
                            "Review the discovered endpoint "
                            "and determine whether it exposes "
                            "sensitive functionality or data."
                        ),
                        confidence="High"
                    )
                )

        except requests.RequestException:
            continue

    return findings
