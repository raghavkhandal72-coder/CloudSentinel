import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

from backend.engine.compliance import ComplianceEngine


class WebhookNotifier:
    """
    Enterprise Webhook Alerting & Notification Engine.
    Dispatches rich security scan alerts to Slack, Microsoft Teams, Discord,
    or generic SIEM webhooks (Splunk, Datadog, Elastic).
    """

    @classmethod
    def format_slack_payload(
        cls,
        findings: list[dict[str, Any]],
        score: int,
        grade: str,
        cloud_target: str = "Multi-Cloud",
    ) -> dict[str, Any]:
        critical = sum(1 for f in findings if str(f.get("risk_level", f.get("severity", ""))).upper() == "CRITICAL")
        high = sum(1 for f in findings if str(f.get("risk_level", f.get("severity", ""))).upper() == "HIGH")

        color = "#22c55e" if grade in ["A+", "A"] else ("#f97316" if grade in ["B", "C"] else "#ef4444")
        top_critical = [
            f for f in findings if str(f.get("risk_level", f.get("severity", ""))).upper() in ["CRITICAL", "HIGH"]
        ][:3]

        fields = [
            {"title": "Posture Grade", "value": f"*{grade}* ({score}/100)", "short": True},
            {"title": "Target Environment", "value": cloud_target.upper(), "short": True},
            {"title": "Critical Violations", "value": f"{critical}", "short": True},
            {"title": "High Violations", "value": f"{high}", "short": True},
        ]

        attachments = [
            {
                "color": color,
                "title": f"CloudSentinel Scan Completed - Grade {grade}",
                "text": f"Scanned {len(findings)} assets. Found {critical} Critical and {high} High risk violations.",
                "fields": fields,
                "footer": "CloudSentinel Enterprise CSPM",
                "ts": int(datetime.now(UTC).timestamp()),
            }
        ]

        if top_critical:
            for item in top_critical:
                res = item.get("resource", item.get("resource_id", "Unknown"))
                issue = item.get("issue", item.get("finding_title", "Unknown"))
                sev = item.get("risk_level", item.get("severity", "HIGH")).upper()
                attachments.append(
                    {
                        "color": "#ef4444" if sev == "CRITICAL" else "#f97316",
                        "title": f"[{sev}] {issue}",
                        "text": f"• Resource: `{res}`\n• Remediation: {item.get('remediation', 'Review in dashboard')}",
                    }
                )

        return {"attachments": attachments}

    @classmethod
    def format_teams_payload(
        cls,
        findings: list[dict[str, Any]],
        score: int,
        grade: str,
        cloud_target: str = "Multi-Cloud",
    ) -> dict[str, Any]:
        critical = sum(1 for f in findings if str(f.get("risk_level", f.get("severity", ""))).upper() == "CRITICAL")
        high = sum(1 for f in findings if str(f.get("risk_level", f.get("severity", ""))).upper() == "HIGH")

        theme_color = "22c55e" if grade in ["A+", "A"] else ("f97316" if grade in ["B", "C"] else "ef4444")

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"CloudSentinel Scan: Grade {grade}",
            "sections": [
                {
                    "activityTitle": f"CloudSentinel Security Audit: Grade {grade} ({score}/100)",
                    "activitySubtitle": f"Target: {cloud_target.upper()} | Completed: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
                    "facts": [
                        {"name": "Executive Grade:", "value": grade},
                        {"name": "Security Score:", "value": f"{score}/100"},
                        {"name": "Critical Violations:", "value": str(critical)},
                        {"name": "High Violations:", "value": str(high)},
                        {"name": "Total Findings:", "value": str(len(findings))},
                    ],
                    "markdown": True,
                }
            ],
        }

    @classmethod
    def format_generic_payload(
        cls,
        findings: list[dict[str, Any]],
        score: int,
        grade: str,
        cloud_target: str = "Multi-Cloud",
    ) -> dict[str, Any]:
        return {
            "source": "CloudSentinel CSPM",
            "timestamp": datetime.now(UTC).isoformat(),
            "target": cloud_target,
            "score": score,
            "grade": grade,
            "critical_count": sum(1 for f in findings if str(f.get("risk_level", "")).upper() == "CRITICAL"),
            "high_count": sum(1 for f in findings if str(f.get("risk_level", "")).upper() == "HIGH"),
            "total_findings": len(findings),
            "findings": findings[:20],
        }

    @classmethod
    def send_notification(
        cls,
        webhook_url: str,
        findings: list[dict[str, Any]],
        cloud_target: str = "Multi-Cloud",
    ) -> dict[str, Any]:
        """
        Sends formatted alert notification to target webhook URL.
        Detects Slack vs Teams vs Generic automatically based on URL.
        """
        if not webhook_url:
            return {"status": "skipped", "reason": "No webhook URL provided"}

        score, grade = ComplianceEngine.calculate_security_score(findings)

        parsed_url = urllib.parse.urlparse(webhook_url)
        if parsed_url.scheme not in ("http", "https"):
            return {"status": "error", "reason": "Webhook URL must use http or https scheme"}

        url_lower = webhook_url.lower()
        if "slack.com" in url_lower:
            payload = cls.format_slack_payload(findings, score, grade, cloud_target)
        elif "office.com" in url_lower or "teams" in url_lower:
            payload = cls.format_teams_payload(findings, score, grade, cloud_target)
        else:
            payload = cls.format_generic_payload(findings, score, grade, cloud_target)

        req_body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=req_body,
            headers={"Content-Type": "application/json", "User-Agent": "CloudSentinel-Notifier/1.0"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
                return {
                    "status": "delivered",
                    "status_code": resp.status,
                    "target": cloud_target,
                    "findings_count": len(findings),
                }
        except urllib.error.HTTPError as e:
            return {"status": "error", "status_code": e.code, "reason": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "reason": str(e)}
