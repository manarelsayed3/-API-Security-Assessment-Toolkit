from scanner.findings import Finding


DOCUMENTATION_ENDPOINTS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger",
    "/docs"
]


def check_documentation(base_url, discovered_endpoints):
    findings = []

    discovered_paths = {
        finding.endpoint.rstrip("/").replace(
            base_url.rstrip("/"),
            "",
            1
        )
        for finding in discovered_endpoints
        if finding.endpoint
    }

    for endpoint in DOCUMENTATION_ENDPOINTS:

        if endpoint in discovered_paths:

            findings.append(
                Finding(
                    severity="INFO",
                    title="API Documentation Endpoint Exposed",
                    category="Misconfiguration",
                    endpoint=f"{base_url.rstrip('/')}{endpoint}",
                    evidence=(
                        f"The documentation endpoint "
                        f"{endpoint} is publicly accessible."
                    ),
                    recommendation=(
                        "Verify whether API documentation "
                        "is intentionally exposed and ensure "
                        "sensitive internal details are not disclosed."
                    ),
                    confidence="High"
                )
            )

    return findings


def check_error_response(response):

    findings = []

    if response.status_code >= 500:

        body = response.text.lower()

        error_indicators = [
            "traceback",
            "stack trace",
            "debug",
            "exception",
            "werkzeug",
            "internal server error"
        ]

        detected = [
            indicator
            for indicator in error_indicators
            if indicator in body
        ]

        if detected:

            findings.append(
                Finding(
                    severity="MEDIUM",
                    title="Verbose Error Information Exposed",
                    category="Misconfiguration",
                    endpoint=response.url,
                    evidence=(
                        f"HTTP {response.status_code} response "
                        f"contains potential error details: "
                        f"{', '.join(detected)}."
                    ),
                    recommendation=(
                        "Disable debug output and avoid exposing "
                        "stack traces, framework details, or "
                        "internal error information to clients."
                    ),
                    confidence="High"
                )
            )

    return findings
