from typing import List, Dict, Any, Optional
from fnmatch import fnmatch
from blastradius.models import Principal, Statement, Finding

DANGEROUS_ACTIONS = {
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:updateassumerolepolicy",
    "lambda:createfunction",
    "ec2:runinstances",
    "sts:assumerole",
}


def detect_misconfigurations(principals: List[Principal]) -> List[Finding]:
    """
    Runs rule-based detection on principals:
    1. wildcard_action (Action: * or service:*)
    2. wildcard_resource (Resource: * on Allow statements)
    3. open_trust (Principal: * in role trust policy)
    4. excess_permission (grants dangerous admin/escalation actions)
    """
    findings: List[Finding] = []
    finding_counter = 1

    for p in principals:
        # Rule 3: open_trust (Roles only)
        if p.kind == "role":
            for trust_entry in p.trust:
                if trust_entry == "*":
                    findings.append(
                        Finding(
                            id=f"F{finding_counter:03d}",
                            rule="open_trust",
                            scanner_severity="MEDIUM",
                            location=p.name,
                            statement_ref=None,
                            detail="Role trust policy permits wildcard Principal (*)",
                        )
                    )
                    finding_counter += 1
                    break

        for idx, st in enumerate(p.statements):
            if st.effect != "Allow":
                continue

            # Rule 1: wildcard_action
            for act in st.actions:
                if act == "*":
                    findings.append(
                        Finding(
                            id=f"F{finding_counter:03d}",
                            rule="wildcard_action",
                            scanner_severity="HIGH",
                            location=p.name,
                            statement_ref=idx,
                            detail="Statement allows global wildcard Action (*)",
                        )
                    )
                    finding_counter += 1
                    break
                elif act.endswith(":*"):
                    severity = "HIGH" if act.lower() in ("iam:*", "sts:*") else "MEDIUM"
                    findings.append(
                        Finding(
                            id=f"F{finding_counter:03d}",
                            rule="wildcard_action",
                            scanner_severity=severity,
                            location=p.name,
                            statement_ref=idx,
                            detail=f"Statement allows wildcard service Action ({act})",
                        )
                    )
                    finding_counter += 1
                    break

            # Rule 2: wildcard_resource
            if "*" in st.resources:
                findings.append(
                    Finding(
                        id=f"F{finding_counter:03d}",
                        rule="wildcard_resource",
                        scanner_severity="MEDIUM",
                        location=p.name,
                        statement_ref=idx,
                        detail="Statement allows unrestricted Resource (*)",
                    )
                )
                finding_counter += 1

            # Rule 4: excess_permission (checks for sensitive escalation primitives)
            dangerous_found = []
            for act in st.actions:
                act_lower = act.lower()
                for dang in DANGEROUS_ACTIONS:
                    if dang == act_lower or fnmatch(act_lower, dang):
                        dangerous_found.append(act)
                        break

            if dangerous_found:
                findings.append(
                    Finding(
                        id=f"F{finding_counter:03d}",
                        rule="excess_permission",
                        scanner_severity="MEDIUM",
                        location=p.name,
                        statement_ref=idx,
                        detail=f"Statement grants high-risk privilege escalation actions: {', '.join(sorted(set(dangerous_found)))}",
                    )
                )
                finding_counter += 1

    return findings

