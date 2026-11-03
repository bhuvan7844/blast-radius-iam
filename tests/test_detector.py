import pytest
import networkx as nx
from blastradius.models import Principal, Statement, Finding
from blastradius.detector import detect_misconfigurations
from blastradius.attach import attach_findings, is_exposed
from blastradius.graph_builder import build_graph


def test_detector_rules():
    role = Principal(
        name="test-role",
        kind="role",
        arn="arn:aws:iam::123:role/test-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
            ),
            Statement(
                effect="Allow",
                actions=["iam:PassRole", "s3:GetObject"],
                resources=["arn:aws:s3:::my-bucket/*"],
            ),
        ],
        trust=["*"],
    )

    findings = detect_misconfigurations([role])
    rules = [f.rule for f in findings]

    assert "open_trust" in rules
    assert "wildcard_action" in rules
    assert "wildcard_resource" in rules
    assert "excess_permission" in rules


def test_attach_and_exposure_worked_example():
    """
    Tests that findings attached to exposed nodes are flagged exposed=True,
    while findings on isolated nodes get exposed=False.
    """
    alice = Principal(
        name="alice",
        kind="user",
        arn="arn:aws:iam::123:user/alice",
        statements=[],
        trust=[],
    )

    # dev-role: open trust, can pass specific role 'admin-role' to Lambda
    dev_role = Principal(
        name="dev-role",
        kind="role",
        arn="arn:aws:iam::123:role/dev-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole"],
                resources=["arn:aws:iam::123:role/admin-role"],
            ),
            Statement(
                effect="Allow",
                actions=["lambda:CreateFunction"],
                resources=["*"],
            ),
        ],
        trust=["*"],  # open trust
    )

    admin_role = Principal(
        name="admin-role",
        kind="role",
        arn="arn:aws:iam::123:role/admin-role",
        statements=[
            Statement(
                effect="Allow",
                actions=["rds:*"],
                resources=["arn:aws:rds:::prod-customer-db"],
            )
        ],
        trust=[],
    )

    # isolated-admin: has High severity wildcard permissions but no path reaches it
    isolated_admin = Principal(
        name="isolated-admin",
        kind="role",
        arn="arn:aws:iam::123:role/isolated-admin",
        statements=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
            )
        ],
        trust=[],  # isolated
    )

    resources = [{"name": "prod-customer-db", "type": "aws_db_instance"}]
    principals = [alice, dev_role, admin_role, isolated_admin]

    G = build_graph(principals, resources)
    findings = detect_misconfigurations(principals)
    attached = attach_findings(G, findings)

    dev_findings = [f for f in attached if f.location == "dev-role"]
    isolated_findings = [f for f in attached if f.location == "isolated-admin"]

    assert len(dev_findings) > 0
    assert len(isolated_findings) > 0

    # dev-role is reachable from alice and EXTERNAL -> exposed = True
    for f in dev_findings:
        assert f.node == "dev-role"
        assert f.exposed is True

    # isolated-admin has no incoming paths from alice or EXTERNAL -> exposed = False
    for f in isolated_findings:
        assert f.node == "isolated-admin"
        assert f.exposed is False
