import json
import tempfile
from pathlib import Path

from backend.scanners.kubernetes import KubernetesScanner


def test_k8s_scanner_detects_privileged_and_root():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "vulnerable-app", "namespace": "prod"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app-container",
                            "image": "nginx",
                            "securityContext": {
                                "privileged": True,
                                "runAsNonRoot": False,
                                "capabilities": {"add": ["SYS_ADMIN"]},
                            },
                        }
                    ]
                }
            }
        },
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(manifest, f)
        temp_path = f.name

    try:
        scanner = KubernetesScanner(target_path=temp_path)
        findings = scanner.scan_all()

        issues = [f["issue"] for f in findings]
        assert any("Privileged container" in i for i in issues)
        assert any("run as root" in i for i in issues)
        assert any("Dangerous Linux capabilities" in i for i in issues)
        assert any("Missing CPU or memory resource limits" in i for i in issues)

        # Check CIS framework tag
        priv_finding = next(f for f in findings if "Privileged" in f["issue"])
        assert priv_finding["frameworks"]["cis_k8s"] == "5.2.2"
        assert priv_finding["severity"] == "CRITICAL"
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_k8s_scanner_detects_host_namespaces():
    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "host-debug-pod", "namespace": "kube-system"},
        "spec": {
            "hostNetwork": True,
            "hostPID": True,
            "containers": [
                {
                    "name": "debug",
                    "image": "busybox",
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
                    "securityContext": {"runAsNonRoot": True, "readOnlyRootFilesystem": True},
                }
            ],
        },
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(pod_manifest, f)
        temp_path = f.name

    try:
        scanner = KubernetesScanner(target_path=temp_path)
        findings = scanner.scan_all()
        issues = [f["issue"] for f in findings]
        assert any("Host namespace sharing" in i for i in issues)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_k8s_clean_workload():
    clean_manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "hardened-app", "namespace": "prod"},
        "spec": {
            "template": {
                "spec": {
                    "serviceAccountName": "app-sa",
                    "automountServiceAccountToken": False,
                    "hostNetwork": False,
                    "hostPID": False,
                    "containers": [
                        {
                            "name": "secure-worker",
                            "image": "distroless",
                            "resources": {"limits": {"cpu": "250m", "memory": "256Mi"}},
                            "securityContext": {
                                "privileged": False,
                                "runAsNonRoot": True,
                                "runAsUser": 10001,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                }
            }
        },
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(clean_manifest, f)
        temp_path = f.name

    try:
        scanner = KubernetesScanner(target_path=temp_path)
        findings = scanner.scan_all()
        assert len(findings) == 0
    finally:
        Path(temp_path).unlink(missing_ok=True)
