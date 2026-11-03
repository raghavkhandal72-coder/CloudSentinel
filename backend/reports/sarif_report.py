import json
import os


def generate_sarif_report(findings: list, output_path: str | None = None) -> dict:
    """
    Generates a SARIF (Static Analysis Results Interchange Format v2.1.0) report
    compatible with GitHub Code Scanning, GitLab Security, and Azure DevOps.
    """
    severity_to_level = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "PASSED": "none",
    }

    rules_dict = {}
    results = []

    for idx, f in enumerate(findings):
        provider = f.get("provider", "Cloud")
        service = f.get("service", "General")
        rule_id = f"CS-{provider}-{service}-{idx + 1}"

        frameworks = f.get("frameworks", {})
        cis_id = frameworks.get("cis_aws") or frameworks.get("cis_azure")
        if cis_id and cis_id != "N/A":
            rule_id = f"CS-{provider}-{service}-CIS-{cis_id.replace('.', '-')}"

        issue = f.get("issue", "Cloud security finding")
        resource = f.get("resource", "Unknown Resource")
        risk_level = f.get("risk_level", f.get("severity", "Medium"))
        level = severity_to_level.get(risk_level, "warning")

        rem = f.get("remediation", "")
        rem_text = rem.get("title", "") if isinstance(rem, dict) else str(rem)

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f"{service}SecurityCheck",
                "shortDescription": {"text": issue},
                "fullDescription": {"text": f"Detected security misconfiguration in {provider} {service}: {issue}"},
                "help": {"text": f"Remediation Guidance:\n{rem_text}"},
                "properties": {
                    "tags": ["security", provider.lower(), service.lower()],
                    "precision": "high",
                },
            }

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{risk_level}] {issue} on resource: {resource}. Remediation: {rem_text}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{provider}/{service}/{resource.replace(' ', '_')}",
                        },
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                    "logicalLocations": [
                        {
                            "name": resource,
                            "kind": "resource",
                        }
                    ],
                }
            ],
            "properties": {
                "riskScore": f.get("risk_score", 0),
                "riskFactors": f.get("risk_factors", []),
                "frameworks": frameworks,
            },
        }
        results.append(result)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudSentinel",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/raghavkhandal72-coder/CloudSentinel",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)

    return sarif_doc
