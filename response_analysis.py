from scanner.findings import Finding


def analyze_response(response):

    findings = []

    # -------------------------
    # Server Header
    # -------------------------

    server = response.headers.get("Server")

    if server:

        findings.append(
            Finding(
                severity="INFO",
                title="Server Header Exposed",
                category="Response Analysis",
                endpoint=response.url,
                evidence=f"Server header value: {server}",
                recommendation=(
                    "Consider minimizing unnecessary "
                    "server information disclosure."
                ),
                confidence="High"
            )
        )

    # -------------------------
    # Content Type
    # -------------------------

    content_type = response.headers.get(
        "Content-Type",
        ""
    )

    if content_type:

        findings.append(
            Finding(
                severity="INFO",
                title="Content Type Identified",
                category="Response Analysis",
                endpoint=response.url,
                evidence=f"Content-Type: {content_type}",
                recommendation=(
                    "Review whether the returned "
                    "content type is expected."
                ),
                confidence="High"
            )
        )

    # -------------------------
    # Redirect Detection
    # -------------------------

    if response.is_redirect:

        findings.append(
            Finding(
                severity="INFO",
                title="Redirect Observed",
                category="Response Analysis",
                endpoint=response.url,
                evidence=(
                    f"HTTP {response.status_code} "
                    f"redirect response detected."
                ),
                recommendation=(
                    "Review redirect destinations "
                    "and authentication flows."
                ),
                confidence="High"
            )
        )

    return findings
