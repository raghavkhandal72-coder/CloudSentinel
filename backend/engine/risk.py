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
        Calculates the risk score for a single finding.
        Updates the finding dictionary with a 'risk_score' and 'risk_level' key.
        """
        base_severity = finding.get('severity', 'Low')
        score = self.SEVERITY_WEIGHTS.get(base_severity, 10)
        
        issue = finding.get('issue', '').lower()
        
        # 1. Exposure (e.g., public internet access) (+20)
        if '0.0.0.0/0' in issue or 'public' in issue or 'internet' in issue:
            score += 20
            
        # 2. Privilege (e.g., AdministratorAccess, Owner, root) (+15)
        if 'administrator' in issue or 'owner' in issue or 'root' in issue or '*' in issue:
            score += 15
            
        # 3. Data Sensitivity (e.g., S3 buckets, RDS/SQL databases) (+15)
        resource = finding.get('resource', '').lower()
        if 's3' in resource or 'database' in resource or 'storage' in resource:
            score += 15
            
        # 4. Exploitability (e.g., unencrypted, missing MFA, plaintext) (+10)
        if 'mfa' in issue or 'encrypt' in issue or 'disabled' in issue or 'unrestricted' in issue:
            score += 10
            
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
        return score

    def evaluate_findings(self, findings: list) -> list:
        for finding in findings:
            self.calculate_risk(finding)
        
        # Sort findings by risk score descending
        return sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
