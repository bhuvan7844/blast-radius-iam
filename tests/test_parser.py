import pytest
from blastradius.parser_json import (
    as_list,
    parse_statement,
    parse_trust_policy,
    parse_json_policy_doc,
    parse_account_export,
)

def test_as_list_normalization():
    assert as_list("s3:GetObject") == ["s3:GetObject"]
    assert as_list(["s3:GetObject", "s3:PutObject"]) == ["s3:GetObject", "s3:PutObject"]
    assert as_list(None) == []

def test_parse_json_policy_doc():
    raw_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }
    principal = parse_json_policy_doc(raw_doc, principal_name="admin_role", kind="role")
    assert principal.name == "admin_role"
    assert len(principal.statements) == 1
    assert principal.statements[0].actions == ["s3:*"]
    assert principal.statements[0].resources == ["*"]

def test_parse_account_export():
    raw_export = {
        "UserDetailList": [
            {
                "UserName": "alice",
                "Arn": "arn:aws:iam::123:user/alice",
                "UserPolicyList": [
                    {
                        "PolicyName": "AssumePolicy",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Resource": "arn:aws:iam::123:role/dev-role"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "RoleDetailList": [
            {
                "RoleName": "dev-role",
                "Arn": "arn:aws:iam::123:role/dev-role",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole"
                        }
                    ]
                },
                "RolePolicyList": []
            }
        ]
    }
    principals = parse_account_export(raw_export)
    assert len(principals) == 2
    alice = next(p for p in principals if p.name == "alice")
    dev_role = next(p for p in principals if p.name == "dev-role")
    
    assert alice.kind == "user"
    assert alice.statements[0].actions == ["sts:AssumeRole"]
    assert dev_role.kind == "role"
    assert dev_role.trust == ["*"]