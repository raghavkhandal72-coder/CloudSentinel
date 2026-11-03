import json
import os
from pathlib import Path
from typing import Any, ClassVar

from backend.models.finding import Finding
from backend.scanners.base import BaseScanner

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class KubernetesScanner(BaseScanner):
    """
    Enterprise Kubernetes (K8s) Security Posture Scanner.
    Audits Kubernetes workload manifests (Deployments, Pods, StatefulSets, DaemonSets, CronJobs)
    against the CIS Kubernetes Benchmark v1.8, SOC 2, and PCI-DSS standards.
    """

    DANGEROUS_CAPS: ClassVar[set[str]] = {
        "SYS_ADMIN",
        "CAP_SYS_ADMIN",
        "NET_ADMIN",
        "CAP_NET_ADMIN",
        "ALL",
        "SYS_PTRACE",
        "CAP_SYS_PTRACE",
        "SYS_RAWIO",
    }

    def __init__(self, target_path: str | None = None):
        super().__init__()
        self.target_path = target_path or os.getenv("K8S_MANIFEST_PATH")
        self.is_authenticated = bool(self.target_path and os.path.exists(self.target_path))

    def _create_finding(
        self,
        service: str,
        resource: str,
        issue: str,
        severity: str,
        evidence: Any,
        remediation: str,
        cis: str = "N/A",
        mitre: str = "N/A",
        soc2: str = "N/A",
        pci_dss: str = "N/A",
        exposure: int = 0,
        privilege: int = 0,
        data_sensitivity: int = 0,
        exploitability: int = 0,
        cli_remediation: str = "",
        terraform_remediation: str = "",
    ) -> dict[str, Any]:
        frameworks = {"cis_k8s": cis, "mitre": mitre}
        if soc2 != "N/A":
            frameworks["soc2"] = soc2
        if pci_dss != "N/A":
            frameworks["pci_dss"] = pci_dss

        return Finding(
            provider="Kubernetes",
            service=service,
            resource=resource,
            issue=issue,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            frameworks=frameworks,
            exposure=exposure,
            privilege=privilege,
            data_sensitivity=data_sensitivity,
            exploitability=exploitability,
            cli_remediation=cli_remediation,
            terraform_remediation=terraform_remediation,
        ).to_dict()

    def parse_manifests(self, path: str) -> list[dict[str, Any]]:
        """Parses manifest files (YAML or JSON) from a file or directory path."""
        p = Path(path)
        if not p.exists():
            return []

        files_to_read = []
        if p.is_dir():
            for ext in ["*.yaml", "*.yml", "*.json"]:
                files_to_read.extend(p.glob(f"**/{ext}"))
        else:
            files_to_read.append(p)

        docs = []
        for file_path in files_to_read:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if file_path.suffix.lower() == ".json":
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        docs.extend(parsed)
                    elif isinstance(parsed, dict):
                        docs.append(parsed)
                elif YAML_AVAILABLE:
                    loaded = yaml.safe_load_all(content)
                    for item in loaded:
                        if isinstance(item, dict):
                            docs.append(item)
                else:
                    # Fallback for simple JSON-compatible YAML
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, dict):
                            docs.append(parsed)
                    except json.JSONDecodeError:
                        pass
            except Exception:  # noqa: BLE001, S112
                continue

        return docs

    def scan_workload(self, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        kind = manifest.get("kind", "")
        metadata = manifest.get("metadata", {})
        name = metadata.get("name", "unnamed-resource")
        namespace = metadata.get("namespace", "default")
        resource_id = f"k8s/{namespace}/{kind}/{name}"

        # Extract pod spec from various Kubernetes workload controllers
        spec = manifest.get("spec", {})
        pod_spec = spec
        if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]:
            pod_spec = spec.get("template", {}).get("spec", {})
        elif kind == "CronJob":
            pod_spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        elif kind != "Pod":
            # Only audit workloads with container specifications
            return []

        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])
        all_containers = containers + init_containers

        # 1. Host Network / Host PID / Host IPC (CIS 5.2.10)
        host_network = pod_spec.get("hostNetwork", False)
        host_pid = pod_spec.get("hostPID", False)
        host_ipc = pod_spec.get("hostIPC", False)
        if host_network or host_pid or host_ipc:
            shared = [k for k, v in [("hostNetwork", host_network), ("hostPID", host_pid), ("hostIPC", host_ipc)] if v]
            findings.append(
                self._create_finding(
                    service="Workload",
                    resource=resource_id,
                    issue=f"Host namespace sharing enabled ({', '.join(shared)})",
                    severity="HIGH",
                    evidence={"shared_namespaces": shared, "kind": kind, "name": name, "namespace": namespace},
                    remediation=f"Disable host namespace sharing in {kind} '{name}'. Set hostNetwork, hostPID, and hostIPC to false.",
                    cis="5.2.10",
                    mitre="T1611",
                    soc2="CC6.6",
                    pci_dss="Req 2.2",
                    exposure=6,
                    privilege=8,
                    exploitability=7,
                    cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='merge' -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"hostNetwork\":false,\"hostPID\":false}}}}}}}}'",
                    terraform_remediation="spec {\n  template {\n    spec {\n      host_network = false\n      host_pid     = false\n    }\n  }\n}",
                )
            )

        # 2. Default Service Account Token Auto-mounting (CIS 5.1.5)
        sa_name = pod_spec.get("serviceAccountName", "default")
        automount = pod_spec.get("automountServiceAccountToken", True)
        if sa_name == "default" and automount is not False:
            findings.append(
                self._create_finding(
                    service="RBAC",
                    resource=resource_id,
                    issue="Default service account token automatically mounted to workload pods",
                    severity="LOW",
                    evidence={"serviceAccountName": sa_name, "automountServiceAccountToken": automount},
                    remediation="Disable automountServiceAccountToken in the Pod spec or use a dedicated non-default ServiceAccount.",
                    cis="5.1.5",
                    mitre="T1078.004",
                    soc2="CC6.1",
                    pci_dss="Req 7.1",
                    exposure=2,
                    privilege=3,
                    exploitability=3,
                    cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='merge' -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"automountServiceAccountToken\":false}}}}}}}}'",
                    terraform_remediation="automount_service_account_token = false",
                )
            )

        # Container-level checks
        pod_sec_context = pod_spec.get("securityContext", {})
        pod_non_root = pod_sec_context.get("runAsNonRoot")

        for c in all_containers:
            c_name = c.get("name", "unknown")
            c_res_id = f"{resource_id}/container/{c_name}"
            sec_context = c.get("securityContext", {})

            # 3. Privileged container (CIS 5.2.2)
            if sec_context.get("privileged") is True:
                findings.append(
                    self._create_finding(
                        service="Workload",
                        resource=c_res_id,
                        issue=f"Privileged container execution enabled in container '{c_name}'",
                        severity="CRITICAL",
                        evidence={"container": c_name, "privileged": True},
                        remediation=f"Remove privileged: true from securityContext of container '{c_name}'. Privileged containers grant root access to the host kernel.",
                        cis="5.2.2",
                        mitre="T1611",
                        soc2="CC6.6",
                        pci_dss="Req 2.2",
                        exposure=9,
                        privilege=10,
                        exploitability=9,
                        cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='json' -p='[{{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/securityContext/privileged\",\"value\":false}}]'",
                        terraform_remediation=f"container {{\n  name = \"{c_name}\"\n  security_context {{\n    privileged = false\n  }}\n}}",
                    )
                )

            # 4. Running as Root (CIS 5.2.6)
            c_non_root = sec_context.get("runAsNonRoot", pod_non_root)
            c_user = sec_context.get("runAsUser", pod_sec_context.get("runAsUser"))
            if c_non_root is False or c_user == 0 or (c_non_root is None and c_user is None):
                findings.append(
                    self._create_finding(
                        service="Workload",
                        resource=c_res_id,
                        issue=f"Container '{c_name}' configured to run as root user (runAsNonRoot is not enforced)",
                        severity="HIGH",
                        evidence={"container": c_name, "runAsNonRoot": c_non_root, "runAsUser": c_user},
                        remediation=f"Set securityContext.runAsNonRoot: true and define a non-zero runAsUser (e.g., 10001) for container '{c_name}'.",
                        cis="5.2.6",
                        mitre="T1068",
                        soc2="CC6.1",
                        pci_dss="Req 2.2",
                        exposure=5,
                        privilege=8,
                        exploitability=6,
                        cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='merge' -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{c_name}\",\"securityContext\":{{\"runAsNonRoot\":true,\"runAsUser\":10001}}}}]}}}}}}}}'",
                        terraform_remediation="security_context {\n  run_as_non_root = true\n  run_as_user     = 10001\n}",
                    )
                )

            # 5. Writable Root Filesystem (CIS 5.2.4)
            read_only_fs = sec_context.get("readOnlyRootFilesystem", False)
            if not read_only_fs:
                findings.append(
                    self._create_finding(
                        service="Workload",
                        resource=c_res_id,
                        issue=f"Root filesystem is writable in container '{c_name}' (readOnlyRootFilesystem is false)",
                        severity="MEDIUM",
                        evidence={"container": c_name, "readOnlyRootFilesystem": read_only_fs},
                        remediation=f"Enforce securityContext.readOnlyRootFilesystem: true for container '{c_name}'. Mount temporary emptyDir volumes for scratch paths if needed.",
                        cis="5.2.4",
                        mitre="T1059",
                        soc2="CC6.6",
                        pci_dss="Req 2.2",
                        exposure=4,
                        privilege=5,
                        exploitability=5,
                        cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='merge' -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{c_name}\",\"securityContext\":{{\"readOnlyRootFilesystem\":true}}}}]}}}}}}}}'",
                        terraform_remediation="security_context {\n  read_only_root_filesystem = true\n}",
                    )
                )

            # 6. Dangerous Capabilities (CIS 5.2.9)
            caps_add = sec_context.get("capabilities", {}).get("add", [])
            flagged_caps = [cap for cap in caps_add if str(cap).upper() in self.DANGEROUS_CAPS]
            if flagged_caps:
                findings.append(
                    self._create_finding(
                        service="Workload",
                        resource=c_res_id,
                        issue=f"Dangerous Linux capabilities ({', '.join(flagged_caps)}) granted to container '{c_name}'",
                        severity="HIGH",
                        evidence={"container": c_name, "dangerous_capabilities": flagged_caps},
                        remediation=f"Drop all capabilities (drop: ['ALL']) and remove {', '.join(flagged_caps)} from container '{c_name}'.",
                        cis="5.2.9",
                        mitre="T1611",
                        soc2="CC6.6",
                        pci_dss="Req 2.2",
                        exposure=6,
                        privilege=8,
                        exploitability=7,
                        cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='merge' -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{c_name}\",\"securityContext\":{{\"capabilities\":{{\"drop\":[\"ALL\"]}}}}}}]}}}}}}}}'",
                        terraform_remediation="capabilities {\n  drop = [\"ALL\"]\n}",
                    )
                )

            # 7. Missing Resource Limits (CIS 5.2.8)
            resources = c.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    self._create_finding(
                        service="Workload",
                        resource=c_res_id,
                        issue=f"Missing CPU or memory resource limits in container '{c_name}'",
                        severity="MEDIUM",
                        evidence={"container": c_name, "limits": limits},
                        remediation=f"Define resources.limits.cpu and resources.limits.memory for container '{c_name}' to prevent DoS via noisy neighbor exhaustion.",
                        cis="5.2.8",
                        mitre="T1499",
                        soc2="CC7.2",
                        pci_dss="Req 2.2",
                        exposure=3,
                        privilege=2,
                        exploitability=4,
                        cli_remediation=f"kubectl patch {kind.lower()} {name} -n {namespace} --type='merge' -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{c_name}\",\"resources\":{{\"limits\":{{\"cpu\":\"500m\",\"memory\":\"512Mi\"}}}}}}]}}}}}}}}'",
                        terraform_remediation="resources {\n  limits = {\n    cpu    = \"500m\"\n    memory = \"512Mi\"\n  }\n}",
                    )
                )

        return findings

    def scan_all(self) -> list[dict[str, Any]]:
        """Scans all manifests at the configured target path."""
        if not self.target_path:
            return []

        manifests = self.parse_manifests(self.target_path)
        all_findings = []
        for m in manifests:
            all_findings.extend(self.scan_workload(m))

        return all_findings
