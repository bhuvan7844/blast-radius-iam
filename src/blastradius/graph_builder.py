import os
import re
import yaml
from fnmatch import fnmatch
from typing import List, Dict, Any, Callable, Union, Optional
import networkx as nx
from blastradius.models import Principal, Statement
from blastradius.escalation import add_escalation_edges


def load_sensitivity_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Loads sensitivity rules from a YAML file, or returns sensible defaults."""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    return {
        "rules": [
            {"match": "*prod*db*", "score": 10},
            {"match": "*rds*", "score": 9},
            {"match": "*secretsmanager*", "score": 9},
            {"match": "*kms*", "score": 8},
            {"match": "*prod*", "score": 8},
            {"match": "*backup*", "score": 7},
            {"match": "*iam*role/*admin*", "score": 9},
            {"match": "*dev*", "score": 2},
            {"match": "*test*", "score": 1},
        ],
        "default": 3,
    }


def get_resource_sensitivity(resource_name: str, config: Dict[str, Any]) -> int:
    """Calculates sensitivity score (1-10) for a given resource name."""
    rules = config.get("rules", [])
    default_score = config.get("default", 3)
    res_lower = resource_name.lower()

    for rule in rules:
        pattern = rule.get("match", "").lower()
        if fnmatch(res_lower, pattern):
            return rule.get("score", default_score)
    return default_score


def infer_service_from_resource(resource_name: str, resource_type: str = "") -> Optional[str]:
    """Infers AWS service (s3, rds, secretsmanager, kms, dynamodb, lambda) from resource info."""
    t = resource_type.lower()
    r = resource_name.lower()

    if "s3" in t or "bucket" in t or "bucket" in r:
        return "s3"
    if "db" in t or "rds" in t or "database" in r or "db" in r:
        return "rds"
    if "secret" in t or "secret" in r:
        return "secretsmanager"
    if "kms" in t or "key" in t:
        return "kms"
    if "dynamodb" in t or "table" in t:
        return "dynamodb"
    if "lambda" in t or "function" in t:
        return "lambda"
    return None


def statement_matches_resource_access(st: Statement, resource_name: str, resource_type: str = "") -> bool:
    """
    Checks if a statement grants data/API access to the specified resource.
    Management actions (iam:*, sts:*) do not count as direct resource access.
    """
    # 1. Match Resource pattern
    res_lower = resource_name.lower()
    matches_resource = any(
        r == "*"
        or fnmatch(res_lower, r.lower())
        or fnmatch(r.lower(), f"*{res_lower}*")
        or fnmatch(f"arn:aws:*:::{res_lower}*", r.lower())
        for r in st.resources
    )
    if not matches_resource:
        return False

    # 2. Match Action pattern
    service = infer_service_from_resource(resource_name, resource_type)

    for act in st.actions:
        a = act.lower()
        if a == "*":
            return True
        # Filter out purely identity/escalation actions
        if a.startswith("iam:") or a.startswith("sts:"):
            continue
        if service:
            if a.startswith(f"{service}:") or (service == "rds" and a.startswith("rds-db:")):
                return True
        else:
            # If service unknown, any non-iam action that explicitly names the resource counts
            if not a.startswith("iam:") and not a.startswith("sts:"):
                return True

    return False


def principal_allowed_resource(principal: Principal, resource_name: str, resource_type: str = "") -> bool:
    """
    Checks if a principal has an Allow statement covering resource_name
    and no matching Deny statement.
    """
    allowed = False

    for st in principal.statements:
        if statement_matches_resource_access(st, resource_name, resource_type):
            if st.effect == "Deny":
                return False
            if st.effect == "Allow":
                allowed = True

    return allowed


def build_graph(
    principals: List[Principal],
    resources: Union[List[str], List[Dict[str, Any]]],
    sensitivity_config: Optional[Dict[str, Any]] = None,
) -> nx.DiGraph:
    """
    Builds a directed reachability graph:
    - Nodes: principals (user/role), resources, EXTERNAL
    - Edges: can_access, can_assume, can_escalate
    """
    if sensitivity_config is None:
        sensitivity_config = load_sensitivity_config()

    G = nx.DiGraph()
    G.add_node("EXTERNAL", kind="external", sensitivity=0)

    # 1. Add Principals
    for p in principals:
        G.add_node(p.name, kind=p.kind, arn=p.arn, obj=p)

    # 2. Add Target Resources
    normalized_resources: List[Dict[str, str]] = []
    for r in resources:
        if isinstance(r, dict):
            r_name = r.get("name", "unknown_resource")
            r_type = r.get("type", "")
        else:
            r_name = str(r)
            r_type = ""
        normalized_resources.append({"name": r_name, "type": r_type})
        sens = get_resource_sensitivity(r_name, sensitivity_config)
        G.add_node(r_name, kind="resource", sensitivity=sens, rtype=r_type)

    # 3. Add 'can_access' edges (Principal -> Resource)
    for p in principals:
        for r_info in normalized_resources:
            r_name = r_info["name"]
            r_type = r_info["type"]
            if principal_allowed_resource(p, r_name, r_type):
                G.add_edge(p.name, r_name, etype="can_access")

    # 4. Add 'can_assume' edges
    roles = [p for p in principals if p.kind == "role"]
    for role in roles:
        for who in role.trust:
            if who == "*":
                # Anyone on the internet or inside the account can assume
                G.add_edge("EXTERNAL", role.name, etype="can_assume")
                for u in principals:
                    if u.name != role.name:
                        G.add_edge(u.name, role.name, etype="can_assume")
            else:
                for p in principals:
                    if p.name == role.name:
                        continue
                    if who == p.arn or who == p.name or fnmatch(p.arn.lower(), who.lower()):
                        G.add_edge(p.name, role.name, etype="can_assume")

        # Also check if any principal has explicit sts:AssumeRole targeting this role
        for p in principals:
            if p.name == role.name:
                continue
            for st in p.statements:
                if st.effect == "Allow":
                    has_assume_act = any(
                        act == "*" or fnmatch(act.lower(), "sts:assumerole") or fnmatch(act.lower(), "sts:*")
                        for act in st.actions
                    )
                    matches_role = any(
                        res == "*" or fnmatch(role.arn.lower(), res.lower()) or fnmatch(role.name.lower(), res.lower())
                        for res in st.resources
                    )
                    if has_assume_act and matches_role:
                        G.add_edge(p.name, role.name, etype="can_assume")

    # 5. Add Privilege-Escalation edges
    add_escalation_edges(G, principals)

    return G
