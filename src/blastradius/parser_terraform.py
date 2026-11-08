import json
import re
from typing import List, Dict, Any, Tuple
import hcl2
from blastradius.models import Statement, Principal
from .parser_json import as_list

KNOWN_RESOURCE_TYPES = {
    "aws_s3_bucket",
    "aws_db_instance",
    "aws_secretsmanager_secret",
    "aws_kms_key",
    "aws_lambda_function",
    "aws_dynamodb_table",
}


def strip_quotes(val: Any) -> Any:
    """Recursively strip surrounding quotes from strings and dict keys."""
    if isinstance(val, str):
        v = val.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        return v
    if isinstance(val, dict):
        return {strip_quotes(k): strip_quotes(v) for k, v in val.items()}
    if isinstance(val, list):
        return [strip_quotes(x) for x in val]
    return val


def _parse_hcl_object(hcl_str: str) -> Dict[str, Any]:
    """Parse an HCL object string by wrapping it as a Terraform variable block."""
    import io
    try:
        wrapped = f"x = {hcl_str}\n"
        result = hcl2.load(io.StringIO(wrapped))
        val = result.get("x", {})
        if isinstance(val, list) and val:
            val = val[0]
        return strip_quotes(val) if isinstance(val, dict) else {}
    except Exception:
        return {}


def clean_json_str(raw: Any) -> Dict[str, Any]:
    """Parse a Terraform string that may contain jsonencode (HCL or JSON) or heredoc JSON."""
    if isinstance(raw, dict):
        return strip_quotes(raw)
    if not isinstance(raw, str):
        return {}

    cleaned = raw.strip()
    # Strip wrapping quotes if present
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()

    # Handle heredocs: <<EOF ... EOF or <<POLICY ... POLICY
    cleaned = re.sub(r"^<<[A-Z_]+\s*", "", cleaned)
    cleaned = re.sub(r"\s*[A-Z_]+$", "", cleaned)
    cleaned = cleaned.strip()

    # Handle ${jsonencode({...})} -> first unwrap ${...}, then unwrap jsonencode(...)
    inner = None
    if cleaned.startswith("${") and cleaned.endswith("}"):
        cleaned = cleaned[2:-1].strip()
    if cleaned.startswith("jsonencode(") and cleaned.endswith(")"):
        inner = cleaned[11:-1]

    if inner is not None:
        # Try JSON first (standard), then HCL object syntax
        try:
            return strip_quotes(json.loads(inner))
        except Exception:
            return _parse_hcl_object(inner)

    try:
        loaded = json.loads(cleaned)
        return strip_quotes(loaded)
    except Exception:
        return {}


def parse_terraform_file(file_path: str) -> Tuple[List[Principal], List[Dict[str, Any]]]:
    """Parse a Terraform file (.tf) and extract Principals and Resource targets."""
    with open(file_path, "r", encoding="utf-8") as f:
        tf_data = hcl2.load(f)

    principals_map: Dict[str, Principal] = {}
    policies_map: Dict[str, List[Statement]] = {}   # tf_resource_name -> statements
    resources: List[Dict[str, Any]] = []

    for block in tf_data.get("resource", []):
        for raw_res_type, instances in block.items():
            res_type = strip_quotes(raw_res_type)
            instances = strip_quotes(instances)

            # Extract managed IAM policies (aws_iam_policy)
            if res_type == "aws_iam_policy":
                for policy_tf_name, cfg in instances.items():
                    policy_doc = clean_json_str(cfg.get("policy", ""))
                    stmts = []
                    for st in policy_doc.get("Statement", []) if isinstance(policy_doc, dict) else []:
                        stmts.append(Statement(
                            effect=st.get("Effect", "Allow"),
                            actions=as_list(st.get("Action", [])),
                            resources=as_list(st.get("Resource", [])),
                            source=policy_tf_name,
                        ))
                    policies_map[policy_tf_name] = stmts

            # Extract target cloud resources
            elif res_type in KNOWN_RESOURCE_TYPES:
                for res_name, _ in instances.items():
                    resources.append({"name": res_name, "type": res_type})

            # Extract IAM Roles
            elif res_type == "aws_iam_role":
                for role_name, config in instances.items():
                    assume_doc = clean_json_str(config.get("assume_role_policy", ""))
                    trust: List[str] = []
                    if assume_doc:
                        statements = assume_doc.get("Statement", [])
                        for st in statements if isinstance(statements, list) else [statements]:
                            p = st.get("Principal", {})
                            if p == "*":
                                trust.append("*")
                            elif isinstance(p, dict):
                                for v in p.values():
                                    trust.extend(v if isinstance(v, list) else [v])

                    actual_role_name = strip_quotes(config.get("name", role_name))
                    principals_map[role_name] = Principal(
                        name=role_name,
                        kind="role",
                        arn=f"arn:aws:iam::123456789012:role/{actual_role_name}",
                        statements=[],
                        trust=trust,
                    )

            # Extract IAM Role Policies (inline JSON)
            elif res_type == "aws_iam_role_policy":
                for policy_name, cfg in instances.items():
                    role_ref = str(cfg.get("role", ""))
                    # Can be "aws_iam_role.dev_role.name", "${aws_iam_role.dev_role.name}", or role name
                    role_name = role_ref
                    match = re.search(r"aws_iam_role\.([a-zA-Z0-9_\-]+)", role_ref)
                    if match:
                        role_name = match.group(1)
                    else:
                        role_name = strip_quotes(role_ref)

                    policy_doc = clean_json_str(cfg.get("policy", ""))
                    statements = []
                    for st in policy_doc.get("Statement", []) if isinstance(policy_doc, dict) else []:
                        statements.append(Statement(
                            effect=st.get("Effect", "Allow"),
                            actions=as_list(st.get("Action", [])),
                            resources=as_list(st.get("Resource", [])),
                            source=policy_name,
                        ))

                    if role_name not in principals_map:
                        principals_map[role_name] = Principal(
                            name=role_name,
                            kind="role",
                            arn=f"arn:aws:iam::123456789012:role/{role_name}",
                            statements=[],
                            trust=[],
                        )
                    principals_map[role_name].statements.extend(statements)

            # Extract IAM Users
            elif res_type == "aws_iam_user":
                for user_name, config in instances.items():
                    actual_user_name = strip_quotes(config.get("name", user_name) if isinstance(config, dict) else user_name)
                    principals_map[user_name] = Principal(
                        name=user_name,
                        kind="user",
                        arn=f"arn:aws:iam::123456789012:user/{actual_user_name}",
                        statements=[],
                        trust=[],
                    )

            # Extract IAM User Policies (inline JSON)
            elif res_type == "aws_iam_user_policy":
                for policy_name, cfg in instances.items():
                    user_ref = str(cfg.get("user", ""))
                    match = re.search(r"aws_iam_user\.([a-zA-Z0-9_\-]+)", user_ref)
                    if match:
                        user_name = match.group(1)
                    else:
                        user_name = strip_quotes(user_ref)

                    policy_doc = clean_json_str(cfg.get("policy", ""))
                    statements = []
                    for st in policy_doc.get("Statement", []) if isinstance(policy_doc, dict) else []:
                        statements.append(Statement(
                            effect=st.get("Effect", "Allow"),
                            actions=as_list(st.get("Action", [])),
                            resources=as_list(st.get("Resource", [])),
                            source=policy_name,
                        ))

                    if user_name not in principals_map:
                        principals_map[user_name] = Principal(
                            name=user_name,
                            kind="user",
                            arn=f"arn:aws:iam::123456789012:user/{user_name}",
                            statements=[],
                            trust=[],
                        )
                    principals_map[user_name].statements.extend(statements)

            # Attach managed policy to a user
            elif res_type == "aws_iam_user_policy_attachment":
                for _, cfg in instances.items():
                    user_ref = str(cfg.get("user", ""))
                    policy_ref = str(cfg.get("policy_arn", ""))
                    match_u = re.search(r"aws_iam_user\.([a-zA-Z0-9_\-]+)", user_ref)
                    match_p = re.search(r"aws_iam_policy\.([a-zA-Z0-9_\-]+)", policy_ref)
                    if not (match_u and match_p):
                        continue
                    user_name = match_u.group(1)
                    policy_tf_name = match_p.group(1)
                    if user_name not in principals_map:
                        principals_map[user_name] = Principal(
                            name=user_name,
                            kind="user",
                            arn=f"arn:aws:iam::123456789012:user/{user_name}",
                            statements=[],
                            trust=[],
                        )
                    principals_map[user_name].statements.extend(policies_map.get(policy_tf_name, []))

            # Attach managed policy to a role
            elif res_type == "aws_iam_role_policy_attachment":
                for _, cfg in instances.items():
                    role_ref = str(cfg.get("role", ""))
                    policy_ref = str(cfg.get("policy_arn", ""))
                    match_r = re.search(r"aws_iam_role\.([a-zA-Z0-9_\-]+)", role_ref)
                    match_p = re.search(r"aws_iam_policy\.([a-zA-Z0-9_\-]+)", policy_ref)
                    if not (match_r and match_p):
                        continue
                    role_name = match_r.group(1)
                    policy_tf_name = match_p.group(1)
                    if role_name not in principals_map:
                        principals_map[role_name] = Principal(
                            name=role_name,
                            kind="role",
                            arn=f"arn:aws:iam::123456789012:role/{role_name}",
                            statements=[],
                            trust=[],
                        )
                    principals_map[role_name].statements.extend(policies_map.get(policy_tf_name, []))

    return list(principals_map.values()), resources
