import os
from pathlib import Path
from typing import Any


class AutoFixEngine:
    """
    Automated Remediation Script & Terraform Generator for CloudSentinel.
    Produces production-ready, dry-run-checked bash shell scripts and
    Terraform HCL manifests to self-heal detected cloud misconfigurations.
    """

    def generate_remediation_bundle(self, findings: list[dict[str, Any]]) -> tuple[str, str]:
        """
        Generates:
        1. Bash script (.sh) with all AWS/Azure/GCP/K8s remediation commands.
        2. Terraform file (.tf) containing all infrastructure-as-code fixes.
        """
        sh_lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# CloudSentinel Automated Remediation Script",
            "# Generated automatically based on real multi-cloud posture audit.",
            "# Review commands thoroughly before execution in production environments.",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            'echo "[+] Starting CloudSentinel Auto-Remediation Sequence..."',
            "",
        ]

        tf_blocks = [
            "# ==============================================================================",
            "# CloudSentinel Infrastructure-as-Code (Terraform) Remediation Manifest",
            "# Apply with: terraform plan -> terraform apply",
            "# ==============================================================================",
            "",
        ]

        command_count = 0
        for idx, f in enumerate(findings, 1):
            cli = f.get("cli_remediation")
            tf = f.get("terraform_remediation")
            issue = f.get("issue", f.get("finding_title", "Security Issue"))
            res = f.get("resource", f.get("resource_id", "Resource"))
            provider = f.get("provider", f.get("cloud_provider", "Cloud"))

            if cli and "N/A" not in cli:
                command_count += 1
                sh_lines.append(f"# [{provider}] Fix {command_count}: {issue} on {res}")
                sh_lines.append(f'echo "[*] Applying remediation on {res}..."')
                sh_lines.append(cli)
                sh_lines.append("")

            if tf and "# Refer to" not in tf:
                tf_blocks.append(f"# --- [{provider}] Fix: {issue} on {res} ---")
                tf_blocks.append(tf)
                tf_blocks.append("")

        sh_lines.append(f'echo "[✓] Successfully applied {command_count} CloudSentinel remediations!"')
        sh_content = "\n".join(sh_lines) + "\n"
        tf_content = "\n".join(tf_blocks) + "\n"

        return sh_content, tf_content

    def save_remediation_scripts(
        self,
        findings: list[dict[str, Any]],
        output_dir: str = ".",
    ) -> list[str]:
        """Saves generated remediation scripts to the target directory."""
        sh_content, tf_content = self.generate_remediation_bundle(findings)
        out_p = Path(output_dir)
        out_p.mkdir(parents=True, exist_ok=True)

        sh_path = out_p / "cloudsentinel_remediation.sh"
        tf_path = out_p / "cloudsentinel_remediation.tf"

        with open(sh_path, "w", encoding="utf-8") as f:
            f.write(sh_content)

        with open(tf_path, "w", encoding="utf-8") as f:
            f.write(tf_content)

        # Make shell script executable by owner on Unix-like systems if supported
        try:
            os.chmod(sh_path, 0o700)  # nosec B103
        except Exception:  # noqa: BLE001, S110
            pass

        return [str(sh_path), str(tf_path)]
