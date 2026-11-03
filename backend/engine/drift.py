from typing import Any


class DriftEngine:
    """
    Security Drift & Regression Detection Engine.
    Compares security findings between a baseline snapshot and the current scan
    to identify newly introduced vulnerabilities vs resolved security issues.
    """

    @staticmethod
    def _get_fingerprint(finding: dict[str, Any]) -> str:
        provider = str(finding.get("provider", finding.get("cloud_provider", "Unknown"))).upper()
        service = str(finding.get("service", "Unknown")).upper()
        resource = str(finding.get("resource", finding.get("resource_id", "Unknown")))
        issue = str(finding.get("issue", finding.get("finding_title", "Unknown")))
        return f"{provider}|{service}|{resource}|{issue}"

    @classmethod
    def calculate_drift(
        cls,
        baseline_findings: list[dict[str, Any]],
        current_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Calculates diff between baseline and current findings.
        Returns:
            {
                "new_findings": [...],
                "resolved_findings": [...],
                "unchanged_findings": [...],
                "summary": {
                    "new_count": int,
                    "resolved_count": int,
                    "unchanged_count": int,
                    "new_critical": int,
                    "new_high": int,
                    "status": "REGRESSION" | "IMPROVED" | "STABLE"
                }
            }
        """
        baseline_map = {cls._get_fingerprint(f): f for f in baseline_findings}
        current_map = {cls._get_fingerprint(f): f for f in current_findings}

        baseline_keys = set(baseline_map.keys())
        current_keys = set(current_map.keys())

        new_keys = current_keys - baseline_keys
        resolved_keys = baseline_keys - current_keys
        unchanged_keys = current_keys & baseline_keys

        new_findings = [current_map[k] for k in new_keys]
        resolved_findings = [baseline_map[k] for k in resolved_keys]
        unchanged_findings = [current_map[k] for k in unchanged_keys]

        # Calculate severity of newly introduced findings
        def _is_sev(f, level):
            return str(f.get("risk_level", f.get("severity", ""))).upper() == level.upper()

        new_critical = sum(1 for f in new_findings if _is_sev(f, "CRITICAL"))
        new_high = sum(1 for f in new_findings if _is_sev(f, "HIGH"))
        new_medium = sum(1 for f in new_findings if _is_sev(f, "MEDIUM"))
        new_low = sum(1 for f in new_findings if _is_sev(f, "LOW"))

        if new_critical > 0 or new_high > 0:
            status = "REGRESSION"
        elif len(resolved_findings) > len(new_findings):
            status = "IMPROVED"
        elif len(new_findings) == 0 and len(resolved_findings) == 0:
            status = "STABLE"
        else:
            status = "REGRESSION" if len(new_findings) > 0 else "STABLE"

        return {
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "unchanged_findings": unchanged_findings,
            "summary": {
                "total_current": len(current_findings),
                "total_baseline": len(baseline_findings),
                "new_count": len(new_findings),
                "resolved_count": len(resolved_findings),
                "unchanged_count": len(unchanged_findings),
                "new_critical": new_critical,
                "new_high": new_high,
                "new_medium": new_medium,
                "new_low": new_low,
                "status": status,
            },
        }
