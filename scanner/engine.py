import requests

from scanner.findings import Finding

from headers import check_headers
from discovery import discover_endpoints
from auth import test_authentication
from idor import test_idor
from response_analysis import analyze_response
from misconfiguration import (
    check_documentation,
    check_error_response
)


class ScannerEngine:

    def __init__(self, target):
        self.target = target.rstrip("/")
        self.findings = []

    def add_findings(self, findings):

        if findings:
            self.findings.extend(findings)

    def run_headers(self, response):

        findings = check_headers(
            response
        )

        self.add_findings(
            findings
        )

    def run_discovery(self):

        findings = discover_endpoints(
            self.target
        )

        self.add_findings(
            findings
        )

        return findings

    def run_authentication(self, endpoints):

        for finding in endpoints:

            endpoint = finding.endpoint

            if not endpoint:
                continue

            findings = test_authentication(
                endpoint
            )

            self.add_findings(
                findings
            )

    def run_idor(
        self,
        endpoint,
        baseline_id,
        object_ids,
        headers=None
    ):

        findings = test_idor(
            base_url=self.target,
            endpoint=endpoint,
            baseline_id=baseline_id,
            object_ids=object_ids,
            headers=headers
        )

        self.add_findings(
            findings
        )

        return findings

    def scan(self):

        try:

            response = requests.get(
                self.target,
                timeout=10,
                allow_redirects=False
            )

            # -------------------------
            # Security Headers
            # -------------------------

            self.run_headers(
                response
            )

            # -------------------------
            # Response Analysis
            # -------------------------

            response_findings = (
                analyze_response(
                    response
                )
            )

            self.add_findings(
                response_findings
            )

            # -------------------------
            # Endpoint Discovery
            # -------------------------

            discovery_findings = (
                self.run_discovery()
            )

            # -------------------------
            # Misconfiguration Checks
            # -------------------------

            misconfiguration_findings = (
                check_documentation(
                    self.target,
                    discovery_findings
                )
            )

            self.add_findings(
                misconfiguration_findings
            )

            error_findings = (
                check_error_response(
                    response
                )
            )

            self.add_findings(
                error_findings
            )

            # -------------------------
            # Authentication
            # -------------------------

            self.run_authentication(
                discovery_findings
            )

            return self.findings

        except requests.RequestException as e:

            self.add_findings([
                Finding(
                    severity="ERROR",
                    title="Scanner Request Failed",
                    category="Scanner",
                    endpoint=self.target,
                    evidence=str(e),
                    recommendation=(
                        "Verify that the target "
                        "is reachable and try "
                        "the scan again."
                    ),
                    confidence="High"
                )
            ])

            return self.findings

    def get_findings(self):

        return self.findings

    def clear(self):

        self.findings.clear()
