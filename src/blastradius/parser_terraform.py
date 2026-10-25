import json
import hcl2
from typing import List, Dict, Any, Tuple
from blastradius.models import Statement, Principal

KNOWN_RESOURCE_TYPES = {
    "aws_s3_bucket", "aws_db_instance", "aws_secretsmanager_secret",
    "aws_kms_key", "aws_lambda_function", "aws_dynamodb_table"
}

def clean_json_str(raw: str) -> Dict[str, Any]:
    """Helper to parse raw or heredocs/jsonencode strings inside Terraform."""
    if not isinstance(raw, str):
        return raw if isinstance(raw, dict) else {}
    cleaned = raw.strip()
    if cleaned.startswith("${jsonencode(") and cleaned.endswith(")}"):
        cleaned = cleaned[13:-2]
    try:
        return json.loads(cleaned)
    except Exception:
        return {}

def parse_terraform_file(file_path: str) -> Tuple[List[Principal], List[Dict[str, Any]]]:
    """
    Parses a Terraform file (.tf) and extracts Principals and Resource targets.
    Returns (principals, target_resources).
    """
    with open(file_path, "r", encoding="utf-8") as f:
        tf_data = hcl2.load(f)

    principals_map: Dict[str, Principal] = {}
    resources: List[Dict[str, Any]] = []

    for block in tf_data.get("resource", []):
        for res_type, instances in block.items():
            # Extract target cloud resources
            if res_type in KNOWN_RESOURCE_TYPES:
                for res_name, _ in instances.items():
                    resources.append({"name": res_name, "type": res_type})

            # Extract IAM Roles
            elif res_type == "aws_iam_role":
                for role_name, config in instances.items():
                    assume_doc = clean_json_str(config.get("assume_role_policy", ""))
                    trust = []
                    if assume_doc:
                        statements = assume_doc.get("Statement", [])
                        for st in statements if isinstance(statements, list) else [statements]:
                            p = st.get("Principal", {})
                            if p == "*":
                                trust.append("*")
                            elif isinstance(p, dict):
                                for v in p.values():
                                    trust.extend(v if isinstance(v, list) else [v])

                    principals_map[role_name] = Principal(
                        name=role_name,
                        kind="role",
                        arn=f"arn:aws:iam::123456789012:role/{role_name}",
                        statements=[],
                        trust=trust
                    )

            # Extract IAM Users
            elif res_type == "aws_iam_user":
                for user_name, _ in instances.items():
                    principals_map[user_name] = Principal(
                        name=user_name,
                        kind="user",
                        arn=f"arn:aws:iam::123456789012:user/{user_name}",
                        statements=[],
                        trust=[]
                    )

    return list(principals_map.values()), resources