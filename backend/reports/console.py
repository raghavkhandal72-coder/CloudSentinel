"""
Enterprise Colorized Console Reporter for CloudSentinel.
Renders executive summaries, posture grades, compliance stats, and actionable findings.
100% cross-platform compatible across Windows (CP1252/UTF-8), Linux, and macOS.
"""

import os
import sys
from typing import Any

from backend.engine.compliance import ComplianceEngine

# Ensure stdout handles encoding gracefully on all operating systems
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001, S110
        pass


class ConsoleReporter:
    # ANSI escape codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    def __init__(self, use_color: bool | None = None):
        if use_color is not None:
            self.use_color = use_color
        else:
            # Enable colors if running in terminal (TTY) or CI
            self.use_color = sys.stdout.isatty() or "GITHUB_ACTIONS" in os.environ

    def _c(self, text: str, *codes: str) -> str:
        if not self.use_color:
            return text
        return "".join(codes) + text + self.RESET

    def get_banner(self) -> str:
        banner = r"""
   ______  __                 __ _____             __   _            __
  / ____/ / /____  __  ______/ // ___/___  ____   / /_ (_)____   ___ / /
 / /     / // __ \/ / / / __  / \__ \/ _ \/ __ \ / __// // __ \ / _ \/ / 
/ /___  / // /_/ / /_/ / /_/ / ___/ /  __/ / / // /_ / // / / //  __/ /  
\____/ /_/ \____/\__,_/\__,_/ /____/ \___/_/ /_/ \__//_//_/ /_/ \___/_/   
    CloudSentinel: Enterprise Multi-Cloud Security Posture Management
"""
        return self._c(banner, self.CYAN, self.BOLD)

    def print_report(self, findings: list[dict[str, Any]], compliance_data: dict[str, Any] | None = None):
        if compliance_data is None:
            engine = ComplianceEngine()
            compliance_data = engine.evaluate_compliance(findings)

        print(self.get_banner())

        score = compliance_data["posture_score"]
        grade = compliance_data["posture_grade"]
        sev = compliance_data["severity_breakdown"]

        # Color based on grade
        grade_color = self.GREEN if grade in ["A+", "A"] else self.YELLOW if grade == "B" else self.RED

        border = "+==============================================================================+"
        print(self._c(border, self.BLUE))
        grade_line = f"|  EXECUTIVE POSTURE GRADE: {grade}  (Score: {score}/100)"
        print(self._c(f"{grade_line:<79}|", self.BOLD, grade_color))
        findings_line = f"|  Findings Summary: {sev['critical']} Critical | {sev['high']} High | {sev['medium']} Medium | {sev['low']} Low"
        print(self._c(f"{findings_line:<79}|", self.WHITE))
        print(self._c(f"|{' ' * 78}|", self.BLUE))

        # Frameworks line
        fws = compliance_data.get("frameworks", {})
        fw_strs = []
        for key in ["cis_aws", "cis_azure", "cis_gcp", "soc2", "pci_dss"]:
            if key in fws and fws[key]["violations_count"] > 0:
                fw_strs.append(f"{key.upper()}: {fws[key]['compliance_percentage']}%")
        if not fw_strs:
            fw_strs = ["CIS AWS: 100%", "CIS Azure: 100%", "SOC 2: 100%"]
        fw_summary = " | ".join(fw_strs)
        fw_line = f"|  Compliance: {fw_summary}"
        print(self._c(f"{fw_line:<79}|", self.CYAN))
        print(self._c(border + "\n", self.BLUE))

        print(self._c("=== DETAILED FINDINGS & REMEDIATION ============================================", self.BOLD, self.WHITE))

        for idx, f in enumerate(findings, 1):
            level = f.get("risk_level", "Medium").upper()
            score_val = f.get("risk_score", 0)
            resource = f.get("resource", "Unknown Resource")
            issue = f.get("issue", "")
            provider = f.get("provider", "Cloud")
            service = f.get("service", "General")

            badge_color = self.RED if level == "CRITICAL" else self.YELLOW if level == "HIGH" else self.CYAN
            badge = self._c(f" [{level}] ", self.BOLD, badge_color)

            print(f"\n{self._c(f'#{idx:02d}', self.DIM)} {badge} {self._c(f'({score_val} pts)', self.DIM)} {self._c(f'[{provider}/{service}]', self.BOLD)} {resource}")
            print(f"    {self._c('Issue:', self.BOLD)} {issue}")

            factors = f.get("risk_factors", [])
            if factors:
                print(f"    {self._c('Risk Factors:', self.BOLD)}")
                for fact in factors:
                    print(f"      * {fact}")

            frameworks = f.get("frameworks", {})
            fw_tags = [f"{k.upper()}: {v}" for k, v in frameworks.items() if v and v != "N/A"]
            if fw_tags:
                print(f"    {self._c('Compliance Tags:', self.BOLD)} {', '.join(fw_tags)}")

            rem = f.get("remediation")
            if rem:
                if isinstance(rem, dict):
                    rem_title = rem.get("title", "")
                    steps = rem.get("steps", [])
                    cli_cmd = rem.get("cli_command", f.get("cli_remediation", ""))
                    tf_code = rem.get("terraform", f.get("terraform_remediation", ""))
                else:
                    rem_title = str(rem)
                    steps = []
                    cli_cmd = f.get("cli_remediation", "")
                    tf_code = f.get("terraform_remediation", "")

                print(f"    {self._c('Remediation:', self.BOLD, self.GREEN)} {rem_title}")
                for s in steps:
                    print(f"      -> {s}")

                if cli_cmd and cli_cmd != "N/A - Review architecture manually":
                    print(f"    {self._c('Quick-Fix CLI:', self.BOLD, self.CYAN)}")
                    print(f"      {self._c('$', self.DIM)} {self._c(cli_cmd, self.WHITE)}")

                if tf_code and not tf_code.startswith("#"):
                    print(f"    {self._c('Terraform IaC Fix:', self.BOLD, self.MAGENTA)}")
                    for line in tf_code.strip().split("\n")[:4]:
                        print(f"      {self._c(line, self.DIM)}")

        print("\n" + self._c("=" * 80, self.DIM) + "\n")
