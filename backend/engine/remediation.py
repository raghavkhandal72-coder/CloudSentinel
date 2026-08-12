class RemediationEngine:
    """
    Remediation Engine for CloudSentinel.
    Default behavior is recommendation only. No destructive changes will be made automatically.
    """
    
    REMEDIATIONS = {
        "public_s3": {
            "title": "Disable public access",
            "steps": [
                "Enable Block Public Access",
                "Review bucket policy",
                "Review ACL"
            ]
        },
        "open_ssh": {
            "title": "Restrict SSH exposure",
            "steps": [
                "Remove 0.0.0.0/0",
                "Allow trusted CIDRs only",
                "Prefer VPN/bastion access"
            ]
        },
        "open_rdp": {
            "title": "Restrict RDP exposure",
            "steps": [
                "Remove 0.0.0.0/0 for port 3389",
                "Use Azure Bastion or AWS Systems Manager",
                "Enforce Just-in-Time (JIT) VM access"
            ]
        },
        "iam_owner": {
            "title": "Apply Least Privilege",
            "steps": [
                "Review necessity of Owner/Administrator role",
                "Scope down to specific resource groups",
                "Use managed identities instead of service principals where possible"
            ]
        },
        "public_blob": {
            "title": "Disable Public Blob Access",
            "steps": [
                "Navigate to Storage Account in Azure Portal",
                "Go to Configuration",
                "Set 'Allow Blob public access' to Disabled",
                "Enforce through Azure Policy"
            ]
        },
        "default": {
            "title": "Manual Review Required",
            "steps": [
                "Review the resource configuration manually.",
                "Ensure compliance with organizational security policies."
            ]
        }
    }
    
    def apply_remediation(self, findings: list) -> list:
        """
        Enriches findings with structured remediation steps based on issue text or resource type.
        """
        for finding in findings:
            issue = finding.get('issue', '').lower()
            
            # Map common issues to structured remediations
            matched_key = None
            if "public" in issue and "bucket" in issue:
                matched_key = "public_s3"
            elif "public blob" in issue:
                matched_key = "public_blob"
            elif "port 22" in issue or "ssh" in issue:
                matched_key = "open_ssh"
            elif "port 3389" in issue or "rdp" in issue:
                matched_key = "open_rdp"
            elif "administrator" in issue or "owner" in issue:
                matched_key = "iam_owner"
            
            if matched_key:
                finding['remediation'] = self.REMEDIATIONS[matched_key]
            else:
                # If there's an existing string remediation, structure it
                existing_rem = finding.get('remediation')
                if existing_rem and isinstance(existing_rem, str):
                    finding['remediation'] = {
                        "title": existing_rem,
                        "steps": ["Apply the recommended fix mentioned in title."]
                    }
                else:
                    finding['remediation'] = self.REMEDIATIONS['default']
        
        return findings
