from typing import Any


class AttackPathEngine:
    """
    Graph-based Toxic Attack Path & Cloud Kill-Chain Correlation Engine.
    Correlates individual security findings across network entry points,
    overprivileged identities, and sensitive data stores to discover complete,
    exploitable attack vectors (Toxic Combinations) similar to Wiz and Prisma Cloud.
    """

    def correlate_attack_paths(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        attack_paths = []

        # 1. Categorize findings
        entry_points = []
        privileges = []
        crown_jewels = []
        k8s_privileged = []
        k8s_host_ns = []

        for f in findings:
            issue = str(f.get("issue", f.get("finding_title", ""))).lower()
            provider = str(f.get("provider", f.get("cloud_provider", "")))

            # Network / Entry Point Detection
            if any(k in issue for k in ["0.0.0.0/0", "port 22", "ssh", "port 3389", "rdp", "public ip", "publicly accessible"]) or ("public" in issue and any(k in issue for k in ["bucket", "blob", "s3", "storage"])):
                entry_points.append(f)

            # Privilege Escalation / Lateral Movement
            if any(k in issue for k in ["administratoraccess", "owner", "user access administrator", "service account key"]):
                privileges.append(f)

            # Crown Jewels / Sensitive Data Assets
            if any(k in issue for k in ["rds", "sql", "database", "key vault", "unencrypted"]):
                crown_jewels.append(f)

            # Kubernetes specific
            if provider.lower() in ["kubernetes", "k8s"]:
                if "privileged" in issue:
                    k8s_privileged.append(f)
                if "host namespace" in issue or "hostnetwork" in issue or "hostpid" in issue:
                    k8s_host_ns.append(f)

        # Toxic Path 1: Internet Exposed Virtual Machine with Administrative Identity accessing Crown Jewels
        if entry_points and privileges:
            entry = entry_points[0]
            priv = privileges[0]
            target_jewel = crown_jewels[0] if crown_jewels else entry

            entry_res = entry.get("resource", entry.get("resource_id", "Internet Gateway"))
            priv_res = priv.get("resource", priv.get("resource_id", "Overprivileged Identity"))
            jewel_res = target_jewel.get("resource", target_jewel.get("resource_id", "Target Cloud Data"))

            kill_chain = [
                {
                    "phase": "Phase 1: Initial Ingress",
                    "action": "Attacker scans public internet and compromises open service",
                    "resource": entry_res,
                    "finding": entry.get("issue", entry.get("finding_title")),
                },
                {
                    "phase": "Phase 2: Privilege Escalation",
                    "action": "Attacker abuses excessive IAM / Role privileges to navigate cloud tenant",
                    "resource": priv_res,
                    "finding": priv.get("issue", priv.get("finding_title")),
                },
                {
                    "phase": "Phase 3: Crown Jewel Exfiltration",
                    "action": "Attacker exfiltrates sensitive database assets and unencrypted storage",
                    "resource": jewel_res,
                    "finding": target_jewel.get("issue", target_jewel.get("finding_title")),
                },
            ]

            ascii_diagram = (
                f"[🌐 INTERNET 0.0.0.0/0]\n"
                f"         │\n"
                f"         ▼ (Brute Force / Ingress Exploit)\n"
                f"   [🚪 Entry: {entry_res}]\n"
                f"         │\n"
                f"         ▼ (Steal IAM Credentials / Elevate Role)\n"
                f"   [🔑 Identity: {priv_res}]\n"
                f"         │\n"
                f"         ▼ (Unrestricted Data Access)\n"
                f"   [💎 Crown Jewel: {jewel_res}] (EXFILTRATION RISK)"
            )

            mermaid_diagram = (
                "graph TD\n"
                '    A["🌐 Internet (0.0.0.0/0)"] -->|Open Ingress| B["🚪 Ingress: ' + entry_res + '"]\n'
                '    B -->|Credential Theft| C["🔑 High Privilege: ' + priv_res + '"]\n'
                '    C -->|Exfiltration| D["💎 Crown Jewel: ' + jewel_res + '"]\n'
                "    style A fill:#ef4444,stroke:#ef4444,color:#fff\n"
                "    style D fill:#dc2626,stroke:#b91c1c,color:#fff"
            )

            attack_paths.append({
                "id": "TOXIC-PATH-01",
                "title": "Toxic Attack Path: Internet Ingress to Admin Privilege to Data Exfiltration",
                "severity": "CRITICAL",
                "risk_score": 98,
                "entry_point": entry_res,
                "privilege_bridge": priv_res,
                "crown_jewel": jewel_res,
                "kill_chain": kill_chain,
                "ascii_diagram": ascii_diagram,
                "mermaid_diagram": mermaid_diagram,
                "remediation_priority": f"Revoke 0.0.0.0/0 ingress on {entry_res} immediately to sever the attack chain at Phase 1.",
            })

        # Toxic Path 2: Kubernetes Privileged Container with Host Namespace Breakout
        if k8s_privileged and k8s_host_ns:
            k_priv = k8s_privileged[0]
            k_host = k8s_host_ns[0]
            k_res = k_priv.get("resource", k_priv.get("resource_id", "k8s-pod"))

            kill_chain = [
                {
                    "phase": "Phase 1: Pod Execution",
                    "action": "Malicious code executes inside container or web shell established",
                    "resource": k_res,
                    "finding": k_priv.get("issue", k_priv.get("finding_title")),
                },
                {
                    "phase": "Phase 2: Host Node Kernel Breakout",
                    "action": "Container breakouts via privileged Linux capabilities directly into host kernel",
                    "resource": k_res,
                    "finding": "Privileged container allows raw root access to host node /dev devices",
                },
                {
                    "phase": "Phase 3: Cluster-Wide Lateral Movement",
                    "action": "Attacker abuses hostNetwork/hostPID to sniff pod traffic and steal node Kubelet credentials",
                    "resource": k_host.get("resource", k_host.get("resource_id", "k8s-cluster")),
                    "finding": k_host.get("issue", k_host.get("finding_title")),
                },
            ]

            ascii_diagram = (
                f"[📦 Container: {k_res}]\n"
                f"         │\n"
                f"         ▼ (Privileged Container Escape)\n"
                f"   [⚡ Host Node Kernel (Root PID 0)]\n"
                f"         │\n"
                f"         ▼ (Host Namespace Sniffing & Kubelet Takeover)\n"
                f"   [☸️ Entire Kubernetes Cluster Compromise]"
            )

            mermaid_diagram = (
                "graph TD\n"
                '    A["📦 Container: ' + k_res + '"] -->|Privileged Escape| B["⚡ Host Node Kernel"]\n'
                '    B -->|Host Namespace Sniffing| C["☸️ Entire K8s Cluster Compromise"]\n'
                "    style A fill:#f97316,stroke:#ea580c,color:#fff\n"
                "    style C fill:#ef4444,stroke:#dc2626,color:#fff"
            )

            attack_paths.append({
                "id": "TOXIC-PATH-02",
                "title": "Toxic Attack Path: Kubernetes Privileged Container Host Node Breakout",
                "severity": "CRITICAL",
                "risk_score": 95,
                "entry_point": k_res,
                "privilege_bridge": "Host Kernel Execution (privileged: true)",
                "crown_jewel": "Underlying Node Infrastructure & K8s Worker Nodes",
                "kill_chain": kill_chain,
                "ascii_diagram": ascii_diagram,
                "mermaid_diagram": mermaid_diagram,
                "remediation_priority": f"Set securityContext.privileged: false on {k_res} to prevent container escape.",
            })

        # Toxic Path 3: Publicly Exposed Unencrypted Database
        if any("rds" in str(f.get("issue")).lower() and "public" in str(f.get("issue")).lower() for f in findings):
            rds_public = next(f for f in findings if "rds" in str(f.get("issue")).lower() and "public" in str(f.get("issue")).lower())
            rds_res = rds_public.get("resource", rds_public.get("resource_id", "Database"))

            kill_chain = [
                {
                    "phase": "Phase 1: Internet Discovery",
                    "action": "Automated Shodan/Censys scanners locate public database endpoint",
                    "resource": rds_res,
                    "finding": "Database has PubliclyAccessible set to true on internet",
                },
                {
                    "phase": "Phase 2: Direct Exfiltration",
                    "action": "Attacker brute-forces database credentials or intercepts unencrypted data traffic",
                    "resource": rds_res,
                    "finding": rds_public.get("issue", rds_public.get("finding_title")),
                },
            ]

            ascii_diagram = (
                f"[🌐 Public Internet]\n"
                f"         │\n"
                f"         ▼ (Direct Connection to DB Port 3306/5432)\n"
                f"   [🗄️ Database: {rds_res}] (DIRECT DATA BREACH RISK)"
            )

            mermaid_diagram = (
                "graph TD\n"
                '    A["🌐 Public Internet"] -->|Direct Connection| B["🗄️ Database: ' + rds_res + '"]\n'
                "    style A fill:#ef4444,stroke:#ef4444,color:#fff\n"
                "    style B fill:#dc2626,stroke:#b91c1c,color:#fff"
            )

            attack_paths.append({
                "id": "TOXIC-PATH-03",
                "title": "Toxic Attack Path: Direct Internet Exposure of Production Database",
                "severity": "CRITICAL",
                "risk_score": 92,
                "entry_point": rds_res,
                "privilege_bridge": "Internet Ingress",
                "crown_jewel": rds_res,
                "kill_chain": kill_chain,
                "ascii_diagram": ascii_diagram,
                "mermaid_diagram": mermaid_diagram,
                "remediation_priority": f"Disable PubliclyAccessible on {rds_res} and move into private database subnets.",
            })

        return attack_paths
