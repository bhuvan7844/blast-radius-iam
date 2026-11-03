from fnmatch import fnmatch
from typing import List, Dict, Any, Set
import networkx as nx
from blastradius.models import Principal, Statement


def statement_grants_action(statement: Statement, target_action: str) -> bool:
    """
    Checks if a statement grants target_action.
    Example: target_action='iam:PassRole' is granted by 'iam:PassRole', 'iam:*', or '*'.
    """
    if statement.effect != "Allow":
        return False
    target = target_action.lower()
    for act in statement.actions:
        pattern = act.lower()
        if pattern == "*" or fnmatch(target, pattern):
            return True
    return False


def principal_grants_action(principal: Principal, target_action: str) -> bool:
    """Checks if any statement of a principal grants target_action."""
    return any(statement_grants_action(st, target_action) for st in principal.statements)


def get_matching_targets(statement: Statement, candidate_principals: List[Principal]) -> List[Principal]:
    """Finds which candidate principals match the Resource patterns in a statement."""
    matched = []
    for p in candidate_principals:
        for res_pattern in statement.resources:
            if res_pattern == "*":
                matched.append(p)
                break
            pat = res_pattern.lower()
            if fnmatch(p.arn.lower(), pat) or fnmatch(p.name.lower(), pat):
                matched.append(p)
                break
    return matched


def add_escalation_edges(G: nx.DiGraph, principals: List[Principal]) -> None:
    """
    Identifies known AWS IAM privilege-escalation primitives
    and adds 'can_escalate' edges to the directed graph G.
    """
    roles = [p for p in principals if p.kind == "role"]
    users = [p for p in principals if p.kind == "user"]

    for p in principals:
        # 1. iam:AttachRolePolicy / iam:PutRolePolicy -> escalate to target role
        for st in p.statements:
            if statement_grants_action(st, "iam:AttachRolePolicy") or statement_grants_action(st, "iam:PutRolePolicy"):
                targets = get_matching_targets(st, roles)
                for target in targets:
                    if target.name != p.name:
                        G.add_edge(p.name, target.name, etype="can_escalate", reason="AttachRolePolicy/PutRolePolicy")

        # 2. iam:AttachUserPolicy / iam:PutUserPolicy -> escalate to target user
        for st in p.statements:
            if statement_grants_action(st, "iam:AttachUserPolicy") or statement_grants_action(st, "iam:PutUserPolicy"):
                targets = get_matching_targets(st, users)
                for target in targets:
                    if target.name != p.name:
                        G.add_edge(p.name, target.name, etype="can_escalate", reason="AttachUserPolicy/PutUserPolicy")

        # 3. iam:PassRole + lambda:CreateFunction -> can execute code as passed role
        has_pass_role = principal_grants_action(p, "iam:PassRole")
        has_lambda_create = principal_grants_action(p, "lambda:CreateFunction")
        if has_pass_role and has_lambda_create:
            for st in p.statements:
                if statement_grants_action(st, "iam:PassRole"):
                    targets = get_matching_targets(st, roles)
                    for target in targets:
                        if target.name != p.name:
                            G.add_edge(p.name, target.name, etype="can_escalate", reason="PassRole+CreateFunction")

        # 4. iam:PassRole + ec2:RunInstances -> can launch instance with passed role
        has_ec2_run = principal_grants_action(p, "ec2:RunInstances")
        if has_pass_role and has_ec2_run:
            for st in p.statements:
                if statement_grants_action(st, "iam:PassRole"):
                    targets = get_matching_targets(st, roles)
                    for target in targets:
                        if target.name != p.name:
                            G.add_edge(p.name, target.name, etype="can_escalate", reason="PassRole+RunInstances")

        # 5. iam:UpdateAssumeRolePolicy -> can update trust policy of role to assume it
        for st in p.statements:
            if statement_grants_action(st, "iam:UpdateAssumeRolePolicy"):
                targets = get_matching_targets(st, roles)
                for target in targets:
                    if target.name != p.name:
                        G.add_edge(p.name, target.name, etype="can_escalate", reason="UpdateAssumeRolePolicy")

        # 6. iam:CreatePolicyVersion -> can edit managed policies to grant full privileges
        if principal_grants_action(p, "iam:CreatePolicyVersion"):
            for target in roles:
                if target.name != p.name:
                    G.add_edge(p.name, target.name, etype="can_escalate", reason="CreatePolicyVersion")
