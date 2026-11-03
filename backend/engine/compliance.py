"""
Enterprise Compliance Matrix & Posture Grading Engine for CloudSentinel.
Evaluates compliance scores across CIS Benchmarks, SOC 2 Type II, PCI-DSS, and HIPAA.
Assigns executive-level security grades (A+ through F).
"""

from typing import Any, ClassVar


class ComplianceEngine:
    FRAMEWORK_NAMES: ClassVar[dict[str, str]] = {
        "cis_aws": "CIS AWS Foundations Benchmark v3.0",
        "cis_azure": "CIS Microsoft Azure Benchmark v2.0",
        "cis_gcp": "CIS Google Cloud Platform Benchmark v2.0",
        "soc2": "SOC 2 Type II Security Controls",
        "pci_dss": "PCI-DSS v4.0 Requirement Baseline",
        "hipaa": "HIPAA Security Rule (45 CFR §164.312)",
    }

    @staticmethod
    def calculate_posture_grade(score: float) -> str:
        """
        Calculates letter grade based on security score (0-100).
        Score 100 is ideal (clean), 0 is completely compromised.
        """
        if score >= 95:
            return "A+"
        if score >= 88:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 45:
            return "D"
        return "F"

    def evaluate_compliance(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Evaluates framework compliance stats and overall posture score from findings.
        """
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get("risk_level") == "Critical")
        high_count = sum(1 for f in findings if f.get("risk_level") == "High")
        medium_count = sum(1 for f in findings if f.get("risk_level") == "Medium")
        low_count = sum(1 for f in findings if f.get("risk_level") == "Low")

        # Deduct penalties: Critical -15, High -8, Medium -4, Low -1
        penalty = (critical_count * 15) + (high_count * 8) + (medium_count * 4) + (low_count * 1)
        posture_score = max(0, min(100, 100 - penalty))
        posture_grade = self.calculate_posture_grade(posture_score)

        # Framework breakdown
        framework_findings: dict[str, list[dict[str, Any]]] = {
            "cis_aws": [],
            "cis_azure": [],
            "cis_gcp": [],
            "soc2": [],
            "pci_dss": [],
            "hipaa": [],
        }

        for f in findings:
            frameworks = f.get("frameworks", {})
            for fw, items in framework_findings.items():
                if frameworks.get(fw):
                    items.append(f)

        framework_stats = {}
        for fw, items in framework_findings.items():
            fw_penalty = sum(
                15 if item.get("risk_level") == "Critical" else
                8 if item.get("risk_level") == "High" else
                4 if item.get("risk_level") == "Medium" else 1
                for item in items
            )
            compliance_pct = max(0, min(100, 100 - fw_penalty))
            framework_stats[fw] = {
                "name": self.FRAMEWORK_NAMES.get(fw, fw),
                "violations_count": len(items),
                "compliance_percentage": compliance_pct,
                "status": "Compliant" if compliance_pct >= 90 else "Action Required",
            }

        return {
            "posture_score": posture_score,
            "posture_grade": posture_grade,
            "total_findings": total_findings,
            "severity_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
            "frameworks": framework_stats,
        }
