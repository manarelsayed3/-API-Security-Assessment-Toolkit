import requests

from scanner.findings import Finding


def test_authentication(url):
    findings = []

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False
        )

        if response.status_code == 401:

            findings.append(
                Finding(
                    severity="INFO",
                    title="Authentication Required",
                    category="Authentication",
                    endpoint=url,
                    evidence=(
                        f"{url} returned HTTP 401 "
                        "without authentication."
                    ),
                    recommendation=(
                        "Authentication appears to be enforced."
                    ),
                    confidence="High"
                )
            )

        elif response.status_code == 403:

            findings.append(
                Finding(
                    severity="INFO",
                    title="Access Restricted",
                    category="Authentication",
                    endpoint=url,
                    evidence=(
                        f"{url} returned HTTP 403 "
                        "without authentication."
                    ),
                    recommendation=(
                        "Access control appears to be enforced."
                    ),
                    confidence="High"
                )
            )

        elif response.status_code == 200:

            findings.append(
                Finding(
                    severity="MEDIUM",
                    title="Endpoint Accessible Without Authentication",
                    category="Authentication",
                    endpoint=url,
                    evidence=(
                        f"{url} returned HTTP 200 "
                        "without authentication."
                    ),
                    recommendation=(
                        "Verify whether this endpoint is "
                        "intentionally public."
                    ),
                    confidence="Medium"
                )
            )

    except requests.RequestException as e:

        findings.append(
            Finding(
                severity="ERROR",
                title="Authentication Test Failed",
                category="Authentication",
                endpoint=url,
                evidence=str(e),
                recommendation=(
                    "Verify that the target is reachable "
                    "and try the test again."
                ),
                confidence="High"
            )
        )

    return findings 
