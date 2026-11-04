import json
import sys
from typing import Any

from backend.engine.compliance import ComplianceEngine
from backend.engine.drift import DriftEngine
from backend.engine.remediation import RemediationEngine
from backend.engine.risk import RiskEngine
from backend.main import generate_mock_findings
from backend.scanners.aws import AWSScanner
from backend.scanners.azure import AzureScanner
from backend.scanners.gcp import GCPScanner
from backend.scanners.kubernetes import KubernetesScanner


class CloudSentinelMCPServer:
    """
    Model Context Protocol (MCP) Server for CloudSentinel.
    Enables AI Agents (Claude Desktop, Cursor, Antigravity, VS Code, LangChain)
    to interactively query multi-cloud posture, run live audits, retrieve
    remediations, and detect security regressions via standard MCP JSON-RPC 2.0.
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "cloudsentinel-mcp"
    SERVER_VERSION = "2.0.0"

    def __init__(self):
        self.cached_findings: list[dict[str, Any]] = []

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Dispatches an incoming JSON-RPC 2.0 request to the appropriate handler."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": self.SERVER_NAME,
                        "version": self.SERVER_VERSION,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                    },
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "cloudsentinel_scan",
                            "description": "Scan cloud environments (AWS, Azure, GCP, Kubernetes, or mock lab) for security misconfigurations.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "target": {
                                        "type": "string",
                                        "description": "Target cloud environment: 'aws', 'azure', 'gcp', 'k8s', 'all', or 'mock'.",
                                        "default": "mock",
                                    },
                                    "k8s_path": {
                                        "type": "string",
                                        "description": "Path to Kubernetes manifest files or directory when target is k8s.",
                                    },
                                },
                            },
                        },
                        {
                            "name": "cloudsentinel_get_posture",
                            "description": "Calculate executive security posture grade (A+ through F) and normalized score (0-100).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                            },
                        },
                        {
                            "name": "cloudsentinel_get_compliance",
                            "description": "Audit compliance pass rates across CIS AWS v3.0, CIS Azure v2.0, CIS GCP v2.0, CIS K8s v1.8, SOC 2, PCI-DSS, or HIPAA.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "framework": {
                                        "type": "string",
                                        "description": "Specific framework key (e.g. cis_aws, cis_azure, cis_gcp, cis_k8s, soc2, pci_dss, hipaa) or 'all'.",
                                        "default": "all",
                                    }
                                },
                            },
                        },
                        {
                            "name": "cloudsentinel_get_remediation",
                            "description": "Retrieve exact copy-paste CLI commands and Terraform HCL snippets to fix a specific security finding.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "issue_type": {
                                        "type": "string",
                                        "description": "Issue type identifier (e.g., 'public_s3', 'open_ssh', 'open_rdp', 'k8s_privileged', 'k8s_root', 'rds_unencrypted').",
                                    }
                                },
                                "required": ["issue_type"],
                            },
                        },
                        {
                            "name": "cloudsentinel_detect_drift",
                            "description": "Compare a baseline findings snapshot against current findings to detect new security regressions vs resolved issues.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "baseline": {
                                        "type": "array",
                                        "description": "List of baseline finding objects to compare against.",
                                    },
                                    "target": {
                                        "type": "string",
                                        "description": "Target environment to scan for comparison (default: 'mock').",
                                        "default": "mock",
                                    },
                                },
                                "required": ["baseline"],
                            },
                        },
                    ]
                },
            }

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            return self._execute_tool(req_id, tool_name, arguments)

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": [
                        {
                            "uri": "cloudsentinel://findings/latest",
                            "name": "Latest Security Findings",
                            "description": "Cached list of security findings from the most recent scan.",
                            "mimeType": "application/json",
                        },
                        {
                            "uri": "cloudsentinel://posture/summary",
                            "name": "Executive Posture Summary",
                            "description": "Executive grade, numeric score, and risk metrics.",
                            "mimeType": "application/json",
                        },
                    ]
                },
            }

        if method == "resources/read":
            uri = params.get("uri")
            if uri == "cloudsentinel://findings/latest":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(self.cached_findings, indent=2),
                            }
                        ]
                    },
                }
            if uri == "cloudsentinel://posture/summary":
                score, grade = ComplianceEngine.calculate_security_score(self.cached_findings)
                summary_data = {
                    "score": score,
                    "grade": grade,
                    "total_findings": len(self.cached_findings),
                }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(summary_data, indent=2),
                            }
                        ]
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }

    def _execute_tool(self, req_id: Any, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "cloudsentinel_scan":
            target = args.get("target", "mock")
            k8s_path = args.get("k8s_path")
            raw_findings = []

            if target == "mock":
                raw_findings.extend(generate_mock_findings())
            else:
                if "aws" in target or target == "all":
                    raw_findings.extend(AWSScanner().scan_all())
                if "azure" in target or target == "all":
                    raw_findings.extend(AzureScanner().scan_all())
                if "gcp" in target or target == "all":
                    raw_findings.extend(GCPScanner().scan_all())
                if "k8s" in target or target == "all":
                    raw_findings.extend(KubernetesScanner(target_path=k8s_path).scan_all())

            risk_engine = RiskEngine()
            evaluated = risk_engine.evaluate_findings(raw_findings)
            rem_engine = RemediationEngine()
            remediated = rem_engine.apply_remediation(evaluated)
            self.cached_findings = remediated

            score, grade = ComplianceEngine.calculate_security_score(remediated)
            result_payload = {
                "target": target,
                "total_findings": len(remediated),
                "score": score,
                "grade": grade,
                "findings": remediated,
            }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(result_payload, indent=2)}]},
            }

        if tool_name == "cloudsentinel_get_posture":
            if not self.cached_findings:
                # auto-populate mock if empty
                self.cached_findings = RemediationEngine().apply_remediation(
                    RiskEngine().evaluate_findings(generate_mock_findings())
                )
            score, grade = ComplianceEngine.calculate_security_score(self.cached_findings)
            crit = sum(1 for f in self.cached_findings if str(f.get("risk_level", "")).upper() == "CRITICAL")
            high = sum(1 for f in self.cached_findings if str(f.get("risk_level", "")).upper() == "HIGH")
            med = sum(1 for f in self.cached_findings if str(f.get("risk_level", "")).upper() == "MEDIUM")
            low = sum(1 for f in self.cached_findings if str(f.get("risk_level", "")).upper() in ["LOW", "PASSED"])

            posture = {
                "grade": grade,
                "score": score,
                "total_findings": len(self.cached_findings),
                "severity_counts": {
                    "critical": crit,
                    "high": high,
                    "medium": med,
                    "low": low,
                },
            }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(posture, indent=2)}]},
            }

        if tool_name == "cloudsentinel_get_compliance":
            if not self.cached_findings:
                self.cached_findings = RemediationEngine().apply_remediation(
                    RiskEngine().evaluate_findings(generate_mock_findings())
                )
            compliance_report = ComplianceEngine().evaluate_compliance(self.cached_findings)
            fw_filter = args.get("framework", "all")
            if fw_filter != "all" and fw_filter in compliance_report["frameworks"]:
                compliance_report = compliance_report["frameworks"][fw_filter]

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(compliance_report, indent=2)}]},
            }

        if tool_name == "cloudsentinel_get_remediation":
            issue_type = args.get("issue_type", "default")
            rem_data = RemediationEngine.REMEDIATIONS.get(
                issue_type, RemediationEngine.REMEDIATIONS["default"]
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(rem_data, indent=2)}]},
            }

        if tool_name == "cloudsentinel_detect_drift":
            baseline = args.get("baseline", [])
            target = args.get("target", "mock")
            if not self.cached_findings:
                raw = generate_mock_findings() if target == "mock" else []
                self.cached_findings = RemediationEngine().apply_remediation(RiskEngine().evaluate_findings(raw))
            drift = DriftEngine.calculate_drift(baseline, self.cached_findings)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(drift, indent=2)}]},
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
        }

    def run_stdio(self):
        """Reads JSON-RPC requests from standard input and writes responses to standard output."""
        sys.stderr.write(f"CloudSentinel MCP Server v{self.SERVER_VERSION} listening on stdio...\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except Exception as e:  # noqa: BLE001
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def main():
    server = CloudSentinelMCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
