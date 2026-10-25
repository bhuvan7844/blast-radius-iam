import json
from typing import List, Dict, Any, Union, Tuple
from blastradius.models import Statement, Principal

def as_list(val: Union[str, List[Any], Dict[str, Any], None]) -> List[Any]:
    """Normalizes a single element, dictionary, or None into a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]

def parse_statement(raw: Dict[str, Any], source: str = "") -> Statement:
    """Parses a raw IAM statement object."""
    return Statement(
        effect=raw.get("Effect", "Allow"),
        actions=as_list(raw.get("Action", [])),
        resources=as_list(raw.get("Resource", [])),
        source=source
    )

def parse_trust_policy(doc: Dict[str, Any]) -> List[str]:
    """Extracts principals allowed to assume a role from an AssumeRolePolicyDocument."""
    who = []
    statements = as_list(doc.get("Statement", []))
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        p = st.get("Principal", {})
        if p == "*":
            who.append("*")
        elif isinstance(p, dict):
            for v in p.values():
                who.extend(as_list(v))
    return who

def parse_json_policy_doc(doc: Dict[str, Any], principal_name: str, kind: str = "role", arn: str = "") -> Principal:
    """Parses a single policy document into a Principal dataclass."""
    statements = [parse_statement(st, source=principal_name) for st in as_list(doc.get("Statement", []))]
    return Principal(
        name=principal_name,
        kind=kind,
        arn=arn or f"arn:aws:iam::123456789012:{kind}/{principal_name}",
        statements=statements,
        trust=parse_trust_policy(doc) if kind == "role" else []
    )

def parse_account_export(data: Dict[str, Any]) -> List[Principal]:
    """
    Parses full AWS authorization exports (aws iam get-account-authorization-details).
    Handles UserDetailList and RoleDetailList.
    """
    principals = []

    # Parse Users
    for user_data in data.get("UserDetailList", []):
        user_name = user_data.get("UserName", "unknown_user")
        user_arn = user_data.get("Arn", f"arn:aws:iam::123456789012:user/{user_name}")
        statements = []

        for pol in user_data.get("UserPolicyList", []):
            policy_doc = pol.get("PolicyDocument", {})
            for st in as_list(policy_doc.get("Statement", [])):
                statements.append(parse_statement(st, source=pol.get("PolicyName", user_name)))

        principals.append(Principal(
            name=user_name,
            kind="user",
            arn=user_arn,
            statements=statements,
            trust=[]
        ))

    # Parse Roles
    for role_data in data.get("RoleDetailList", []):
        role_name = role_data.get("RoleName", "unknown_role")
        role_arn = role_data.get("Arn", f"arn:aws:iam::123456789012:role/{role_name}")
        trust_doc = role_data.get("AssumeRolePolicyDocument", {})
        trust_principals = parse_trust_policy(trust_doc)
        statements = []

        for pol in role_data.get("RolePolicyList", []):
            policy_doc = pol.get("PolicyDocument", {})
            for st in as_list(policy_doc.get("Statement", [])):
                statements.append(parse_statement(st, source=pol.get("PolicyName", role_name)))

        principals.append(Principal(
            name=role_name,
            kind="role",
            arn=role_arn,
            statements=statements,
            trust=trust_principals
        ))

    return principals