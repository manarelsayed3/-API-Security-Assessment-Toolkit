import json
from datetime import datetime
from pathlib import Path


SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "ERROR"
]


def build_report(target, findings):

    severity_counts = {
        severity: 0
        for severity in SEVERITY_ORDER
    }

    for finding in findings:

        severity = finding.severity.upper()

        if severity not in severity_counts:
            severity_counts[severity] = 0

        severity_counts[severity] += 1

    report = {
        "target": target,
        "scan_time": datetime.now().astimezone().isoformat(),

        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts
        },

        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    return report


def save_json_report(
    target,
    findings,
    output_file="report.json"
):

    report = build_report(
        target,
        findings
    )

    Path(output_file).write_text(
        json.dumps(
            report,
            indent=4
        ),
        encoding="utf-8"
    )

    return output_file


def save_markdown_report(
    target,
    findings,
    output_file="report.md"
):

    report = build_report(
        target,
        findings
    )

    summary = report["summary"]
    severity_counts = summary["severity_counts"]

    lines = []

    lines.append("# API Security Assessment Report")
    lines.append("")

    lines.append("## Target")
    lines.append("")
    lines.append(target)
    lines.append("")

    lines.append("## Scan Information")
    lines.append("")

    lines.append(
        f"- Scan Time: {report['scan_time']}"
    )

    lines.append(
        f"- Total Findings: "
        f"{summary['total_findings']}"
    )

    lines.append("")

    lines.append("## Severity Summary")
    lines.append("")

    for severity in SEVERITY_ORDER:

        count = severity_counts.get(
            severity,
            0
        )

        lines.append(
            f"- **{severity}:** {count}"
        )

    lines.append("")

    lines.append("## Findings")
    lines.append("")

    if not findings:

        lines.append(
            "No findings were detected."
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            lines.append(
                f"### {index}. "
                f"[{finding.severity}] "
                f"{finding.title}"
            )

            lines.append("")

            lines.append(
                f"**Category:** "
                f"{finding.category}"
            )

            lines.append("")

            if finding.endpoint:

                lines.append(
                    f"**Endpoint:** "
                    f"`{finding.endpoint}`"
                )

                lines.append("")

            lines.append(
                f"**Confidence:** "
                f"{finding.confidence}"
            )

            lines.append("")

            # -------------------------
            # HTTP Evidence
            # -------------------------

            if finding.method:

                lines.append(
                    f"**HTTP Method:** "
                    f"`{finding.method}`"
                )

                lines.append("")

            if finding.status_code is not None:

                lines.append(
                    f"**HTTP Status:** "
                    f"`{finding.status_code}`"
                )

                lines.append("")

            lines.append("**Evidence:**")
            lines.append("")

            lines.append(
                f"> {finding.evidence}"
            )

            lines.append("")

            lines.append(
                "**Recommendation:**"
            )

            lines.append("")

            lines.append(
                finding.recommendation
            )

            lines.append("")

            lines.append("---")
            lines.append("")

    Path(output_file).write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    return output_file
