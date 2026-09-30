from scanner.findings import Finding


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]


def check_headers(response):
    findings = []

    is_https = response.url.lower().startswith("https://")

    for header in SECURITY_HEADERS:

        # HSTS only applies to HTTPS
        if header == "Strict-Transport-Security" and not is_https:
            continue

        if header not in response.headers:

            findings.append(
                Finding(
                    severity="LOW",
                    title=f"Missing Security Header: {header}",
                    category="Security Headers",
                    endpoint=response.url,
                    evidence=(
                        f"The response does not contain "
                        f"the {header} header."
                    ),
                    recommendation=(
                        f"Consider configuring the {header} "
                        f"header according to the application's "
                        f"security requirements."
                    ),
                    confidence="High"
                )
            )

    return findings
