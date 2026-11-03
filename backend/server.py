import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from backend.engine.compliance import ComplianceEngine
from backend.engine.remediation import RemediationEngine
from backend.engine.risk import RiskEngine
from backend.main import generate_mock_findings
from backend.scanners.aws import AWSScanner
from backend.scanners.azure import AzureScanner
from backend.scanners.gcp import GCPScanner

_cached_findings: list[dict] = []


def run_scan(target: str = "mock") -> list[dict]:
    global _cached_findings
    findings = []

    if target == "mock":
        findings.extend(generate_mock_findings())
    else:
        if "aws" in target or target == "all":
            aws = AWSScanner()
            findings.extend(aws.scan_all())
        if "azure" in target or target == "all":
            azure = AzureScanner()
            findings.extend(azure.scan_all())
        if "gcp" in target or target == "all":
            gcp = GCPScanner()
            findings.extend(gcp.scan_all())

    risk_engine = RiskEngine()
    evaluated = risk_engine.evaluate_findings(findings)

    rem_engine = RemediationEngine()
    remediated = rem_engine.apply_remediation(evaluated)

    normalized = []
    for f in remediated:
        rem = f.get("remediation", "")
        if isinstance(rem, dict):
            steps = " ".join(rem.get("steps", []))
            rem_str = f"{rem.get('title', '')}: {steps}"
        else:
            rem_str = str(rem)

        factors = f.get("risk_factors", [])
        frameworks = f.get("frameworks", {})
        cis = frameworks.get("cis_aws") or frameworks.get("cis_azure") or "N/A"

        norm_item = {
            "id": f.get("id", str(uuid.uuid4())[:8]),
            "cloud_provider": f.get("provider", "Cloud"),
            "resource_id": f.get("resource", "Unknown Resource"),
            "finding_title": f.get("issue", "Unknown Issue"),
            "why_it_matters": "; ".join(factors) if factors else "Security misconfiguration detected.",
            "evidence": str(f.get("evidence", "No evidence recorded")),
            "cis_benchmark": f"CIS {cis}" if cis != "N/A" else "N/A",
            "risk_level": f.get("risk_level", "Medium").upper(),
            "risk_score": f.get("risk_score", 0),
            "remediation": rem_str,
            "raw": f,
        }
        normalized.append(norm_item)

    _cached_findings = normalized
    return normalized


def calculate_dashboard_stats(findings: list[dict]) -> dict:
    critical = sum(1 for f in findings if f.get("risk_level") == "CRITICAL")
    high = sum(1 for f in findings if f.get("risk_level") == "HIGH")
    medium = sum(1 for f in findings if f.get("risk_level") == "MEDIUM")
    low = sum(1 for f in findings if f.get("risk_level") in ["LOW", "PASSED"])

    # Score calculation: 100 base, deducted by finding severities
    deduction = (critical * 20) + (high * 10) + (medium * 5)
    overall_score = max(0, 100 - deduction)
    grade = ComplianceEngine.calculate_posture_grade(overall_score)

    return {
        "score": overall_score,
        "grade": grade,
        "critical": critical,
        "high": high,
        "medium": medium,
        "passed": low,
        "total_findings": len(findings),
    }


class CloudSentinelAPIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path in ["/api/stats", "/api/stats/"]:
            if not _cached_findings:
                run_scan("mock")
            stats = calculate_dashboard_stats(_cached_findings)
            self._send_json(stats)
            return

        if self.path in ["/api/findings", "/api/findings/"]:
            if not _cached_findings:
                run_scan("mock")
            self._send_json(_cached_findings)
            return

        # Serve frontend index.html when root or dashboard requested
        if self.path in ["/", "/index.html", "/dashboard"]:
            frontend_index = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
            if os.path.exists(frontend_index):
                with open(frontend_index, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return

        self.send_response(404)
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self):
        if self.path in ["/api/scan", "/api/scan/"]:
            findings = run_scan("mock")
            stats = calculate_dashboard_stats(findings)
            self._send_json({"status": "scan_completed", "stats": stats, "findings_count": len(findings)})
            return

        self.send_response(404)
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(b"Not Found")

    def _send_json(self, data, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Clean logging
        pass


def start_server(host: str | None = None, port: int | None = None):
    if host is None:
        host = os.getenv("HOST", "127.0.0.1")
    if port is None:
        port = int(os.getenv("PORT", "8000"))
    # Initialize cache with mock scan on startup
    run_scan("mock")
    server = ThreadingHTTPServer((host, port), CloudSentinelAPIHandler)
    print(f"CloudSentinel API Server running at http://{host}:{port}/")
    print(f"Access Web Dashboard at http://{host}:{port}/ or connect via frontend")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    start_server()
