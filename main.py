from scanner.engine import ScannerEngine
from scanner.reporting import (
    save_json_report,
    save_markdown_report
)


def print_findings(findings):

    if not findings:
        print("\nNo findings detected.")
        return

    for finding in findings:

        print("=" * 60)

        print(
            f"[{finding.severity}] "
            f"{finding.title}"
        )

        print(
            f"Category: "
            f"{finding.category}"
        )

        if finding.endpoint:
            print(
                f"Endpoint: "
                f"{finding.endpoint}"
            )

        print(
            f"Evidence: "
            f"{finding.evidence}"
        )

        print(
            f"Recommendation: "
            f"{finding.recommendation}"
        )

        print(
            f"Confidence: "
            f"{finding.confidence}"
        )

    print("=" * 60)


def run_bola_test(engine):

    print("\n" + "=" * 60)
    print("CONTROLLED BOLA / IDOR TEST")
    print("=" * 60)

    endpoint = input(
        "Authorization endpoint "
        "(example: /api/users): "
    ).strip()

    baseline_id = input(
        "Baseline object ID: "
    ).strip()

    object_ids_input = input(
        "Object IDs to test "
        "(comma-separated): "
    ).strip()

    object_ids = [
        object_id.strip()
        for object_id in object_ids_input.split(",")
        if object_id.strip()
    ]

    header_name = input(
        "Authentication header name "
        "(example: X-User-ID): "
    ).strip()

    header_value = input(
        "Authentication header value: "
    ).strip()

    headers = {}

    if header_name and header_value:
        headers[header_name] = header_value

    engine.run_idor(
        endpoint=endpoint,
        baseline_id=baseline_id,
        object_ids=object_ids,
        headers=headers
    )


def main():

    target = input(
        "Target URL: "
    ).strip()

    print("\n" + "=" * 60)
    print("API SECURITY ASSESSMENT TOOLKIT")
    print("=" * 60)

    engine = ScannerEngine(
        target
    )

    # -------------------------
    # Standard Security Scan
    # -------------------------

    engine.scan()

    # -------------------------
    # Controlled BOLA / IDOR
    # -------------------------

    run_bola = input(
        "\nRun controlled BOLA / IDOR test? [y/N]: "
    ).strip().lower()

    if run_bola == "y":

        run_bola_test(
            engine
        )

        print(
            "\nBOLA / IDOR test completed."
        )

    # -------------------------
    # Get All Findings
    # -------------------------

    findings = engine.get_findings()

    # -------------------------
    # Display Findings
    # -------------------------

    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)

    print_findings(
        findings
    )

    # -------------------------
    # Generate Reports
    # -------------------------

    json_report = save_json_report(
        target,
        findings,
        "report.json"
    )

    markdown_report = save_markdown_report(
        target,
        findings,
        "report.md"
    )

    print("\n" + "=" * 60)
    print("REPORTS GENERATED")
    print("=" * 60)

    print(
        f"JSON Report: "
        f"{json_report}"
    )

    print(
        f"Markdown Report: "
        f"{markdown_report}"
    )

    print("\nScan completed.")


if __name__ == "__main__":
    main()
