import requests

from scanner.findings import Finding


def test_idor(
    base_url,
    endpoint,
    baseline_id,
    object_ids,
    headers=None
):
    findings = []

    base_url = base_url.rstrip("/")

    endpoint = "/" + endpoint.lstrip("/")

    baseline_url = (
        f"{base_url}{endpoint}/{baseline_id}"
    )

    try:

        # --------------------------------
        # Baseline Request
        # --------------------------------

        baseline_response = requests.get(
            baseline_url,
            headers=headers,
            timeout=10
        )

        if baseline_response.status_code != 200:

            findings.append(
                Finding(
                    severity="INFO",
                    title="IDOR Test Could Not Be Performed",
                    category="Authorization",
                    endpoint=baseline_url,
                    evidence=(
                        f"Baseline object {baseline_id} "
                        f"returned HTTP "
                        f"{baseline_response.status_code}."
                    ),
                    recommendation=(
                        "Provide valid authentication "
                        "and an object owned by the "
                        "test user."
                    ),
                    confidence="High",
                    method="GET",
                    status_code=baseline_response.status_code
                )
            )

            return findings

        # --------------------------------
        # Response Validation
        # --------------------------------

        content_type = baseline_response.headers.get(
            "Content-Type",
            ""
        ).lower()

        # Ignore HTML pages such as login pages
        # or frontend fallback pages.

        if "text/html" in content_type:

            findings.append(
                Finding(
                    severity="INFO",
                    title="IDOR Test Skipped",
                    category="Authorization",
                    endpoint=baseline_url,
                    evidence=(
                        "Baseline response appears to be "
                        "HTML rather than an API object."
                    ),
                    recommendation=(
                        "Use a valid API endpoint that "
                        "returns JSON object data."
                    ),
                    confidence="High",
                    method="GET",
                    status_code=baseline_response.status_code
                )
            )

            return findings

        # Require JSON responses for object testing.

        if "application/json" not in content_type:

            findings.append(
                Finding(
                    severity="INFO",
                    title="IDOR Test Skipped",
                    category="Authorization",
                    endpoint=baseline_url,
                    evidence=(
                        f"Unexpected baseline content type: "
                        f"{content_type or 'unknown'}."
                    ),
                    recommendation=(
                        "Verify that the endpoint returns "
                        "JSON object data before testing "
                        "for BOLA."
                    ),
                    confidence="High",
                    method="GET",
                    status_code=baseline_response.status_code
                )
            )

            return findings

        # --------------------------------
        # Test Additional Objects
        # --------------------------------

        for object_id in object_ids:

            target_url = (
                f"{base_url}{endpoint}/{object_id}"
            )

            response = requests.get(
                target_url,
                headers=headers,
                timeout=10
            )

            # --------------------------------
            # Validate Target Response
            # --------------------------------

            target_content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            # If the target returns HTML,
            # do not treat HTTP 200 as BOLA.

            if "text/html" in target_content_type:

                findings.append(
                    Finding(
                        severity="INFO",
                        title="Possible Generic Response",
                        category="Authorization",
                        endpoint=target_url,
                        evidence=(
                            f"Object {object_id} returned "
                            f"HTTP {response.status_code} "
                            "with an HTML response."
                        ),
                        recommendation=(
                            "Verify that the endpoint returns "
                            "actual API object data."
                        ),
                        confidence="High",
                        method="GET",
                        status_code=response.status_code
                    )
                )

                continue

            # --------------------------------
            # Generic Response Detection
            # --------------------------------

            if (
                baseline_response.status_code == 200
                and response.status_code == 200
                and baseline_response.text == response.text
            ):

                findings.append(
                    Finding(
                        severity="INFO",
                        title="Possible Generic Response",
                        category="Authorization",
                        endpoint=target_url,
                        evidence=(
                            "Baseline and target objects "
                            "returned identical content."
                        ),
                        recommendation=(
                            "Verify that the endpoint returns "
                            "unique object data before "
                            "confirming BOLA."
                        ),
                        confidence="Medium",
                        method="GET",
                        status_code=response.status_code
                    )
                )

                continue

            # --------------------------------
            # Potential BOLA / IDOR
            # --------------------------------

            if response.status_code == 200:

                findings.append(
                    Finding(
                        severity="HIGH",
                        title="Potential IDOR / BOLA",
                        category="Authorization",
                        endpoint=target_url,
                        evidence=(
                            f"Baseline object {baseline_id} "
                            f"returned HTTP 200, while object "
                            f"{object_id} was also accessible "
                            f"with HTTP 200 and returned "
                            "different response content."
                        ),
                        recommendation=(
                            "Verify server-side authorization "
                            "for every object request."
                        ),
                        confidence="High",
                        method="GET",
                        status_code=response.status_code
                    )
                )

            # --------------------------------
            # Authorization Enforced
            # --------------------------------

            elif response.status_code in [
                401,
                403,
                404
            ]:

                findings.append(
                    Finding(
                        severity="INFO",
                        title="Object-Level Authorization Enforced",
                        category="Authorization",
                        endpoint=target_url,
                        evidence=(
                            f"Baseline object {baseline_id} "
                            f"returned HTTP 200. Object "
                            f"{object_id} returned HTTP "
                            f"{response.status_code}."
                        ),
                        recommendation=(
                            "Authorization appears "
                            "to be enforced for "
                            "this object."
                        ),
                        confidence="High",
                        method="GET",
                        status_code=response.status_code
                    )
                )

            # --------------------------------
            # Unexpected Response
            # --------------------------------

            else:

                findings.append(
                    Finding(
                        severity="INFO",
                        title="Unexpected Authorization Response",
                        category="Authorization",
                        endpoint=target_url,
                        evidence=(
                            f"Object {object_id} "
                            f"returned HTTP "
                            f"{response.status_code}."
                        ),
                        recommendation=(
                            "Review the endpoint's "
                            "authorization behavior."
                        ),
                        confidence="Medium",
                        method="GET",
                        status_code=response.status_code
                    )
                )

    except requests.RequestException as e:

        findings.append(
            Finding(
                severity="ERROR",
                title="IDOR Test Failed",
                category="Authorization",
                endpoint=baseline_url,
                evidence=str(e),
                recommendation=(
                    "Verify that the target "
                    "is reachable."
                ),
                confidence="High",
                method="GET"
            )
        )

    return findings
