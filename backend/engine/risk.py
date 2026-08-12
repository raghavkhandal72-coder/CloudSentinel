class RiskEngine:
    """
    Risk Engine for calculating a standardized Risk Score out of 100.
    Formula: Risk Score = Severity + Exposure + Privilege + Data Sensitivity + Exploitability
    """

    SEVERITY_WEIGHTS = {
        "Critical": 40,
        "High": 30,
        "Medium": 20,
        "Low": 10,
        "PASSED": 0
    }

    def calculate_risk(self, finding: dict) -> int:
        """
        Calculates the risk score for a single finding based on explicit attributes.
        Updates the finding dictionary with 'risk_score', 'risk_level', and 'risk_factors'.
        """
        base_severity = finding.get('severity', 'Low')
        severity_score = self.SEVERITY_WEIGHTS.get(base_severity, 10)
        
        exposure = finding.get("exposure", 0)
        privilege = finding.get("privilege", 0)
        data_sensitivity = finding.get("data_sensitivity", 0)
        exploitability = finding.get("exploitability", 0)
        
        score = severity_score + exposure + privilege + data_sensitivity + exploitability
        
        # Cap score at 100
        score = min(score, 100)
        
        # Calculate new risk level string
        if score >= 85:
            finding['risk_level'] = 'Critical'
        elif score >= 65:
            finding['risk_level'] = 'High'
        elif score >= 40:
            finding['risk_level'] = 'Medium'
        elif score > 0:
            finding['risk_level'] = 'Low'
        else:
            finding['risk_level'] = 'PASSED'
            
        finding['risk_score'] = score
        
        # Generate risk factors explanation
        factors = []
        if exposure > 0:
            factors.append("Internet or broadly exposed")
        if privilege > 0:
            factors.append("High privileges granted")
        if data_sensitivity > 0:
            factors.append("Sensitive data or storage resource")
        if exploitability > 0:
            factors.append("Easily exploitable configuration (e.g. unencrypted, no MFA)")
        if severity_score >= 30:
            factors.append(f"Base severity is {base_severity}")
            
        finding['risk_factors'] = factors
        
        return score

    def evaluate_findings(self, findings: list) -> list:
        for finding in findings:
            self.calculate_risk(finding)
        
        # Sort findings by risk score descending
        return sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
